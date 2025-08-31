
import tkinter as tk
from tkinter import simpledialog
from tkinter import messagebox, ttk
import psycopg2
import psycopg2.extras
from decimal import Decimal
from datetime import datetime
import os, random, string, hashlib, binascii, time

CONNECTION_STRING = os.getenv(
    "CRDB_URL",
    "postgresql://<USERNAME>:<PASSWORD>@potent-cougar-15371.j77.aws-ap-south-1.cockroachlabs.cloud:26257/defaultdb?sslmode=require"
)


def hash_password(password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return binascii.hexlify(salt).decode() + "$" + binascii.hexlify(dk).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = binascii.unhexlify(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
        return binascii.hexlify(dk).decode() == hash_hex
    except Exception:
        return False


def generate_account_no(cur) -> str:
    cur.execute("SELECT account_no FROM users ORDER BY id DESC LIMIT 1;")
    row = cur.fetchone()
    if not row or not row[0]:
        return "000001"
    val = row[0]
    try:
        last = int(val)
    except Exception:
        cur.execute("SELECT account_no FROM users;")
        rows = cur.fetchall()
        nums = []
        for r in rows:
            try:
                nums.append(int(r[0]))
            except Exception:
                continue
        last = max(nums) if nums else 0
    return str(last + 1).zfill(6)


class DB:
    def __init__(self, conn_str: str):
        self.conn = psycopg2.connect(conn_str)
        self.conn.set_session(autocommit=False)
        self.ensure_schema()

    def close(self):
        try:
            self.conn.close()
        except:
            pass

    def ensure_schema(self):
        # Create database in autocommit mode
        with self.conn.cursor() as cur:
            self.conn.set_session(autocommit=True)
            cur.execute("CREATE DATABASE IF NOT EXISTS banking;")
            self.conn.set_session(autocommit=False)

        with self.conn.cursor() as cur:
            cur.execute("SET DATABASE = banking;")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username STRING UNIQUE NOT NULL,
                password_hash STRING NOT NULL,
                account_no STRING UNIQUE NOT NULL,
                account_name STRING NOT NULL,
                balance DECIMAL NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                account_no STRING NOT NULL,
                amount DECIMAL NOT NULL,
                txn_type STRING NOT NULL,
                counterparty STRING,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );""")
            self.conn.commit()

    # --- User ops ---
    def create_user(self, username: str, password: str, account_name: str, initial_deposit: Decimal = Decimal("0")):
        retries = 5
        while True:
            try:
                with self.conn.cursor() as cur:
                    cur.execute("SET DATABASE = banking;")
                    account_no = generate_account_no(cur)
                    cur.execute("SELECT 1 FROM users WHERE account_no=%s;", (account_no,))
                    while cur.fetchone():
                        account_no = str(int(account_no) + 1).zfill(6)
                        cur.execute("SELECT 1 FROM users WHERE account_no=%s;", (account_no,))

                    pwh = hash_password(password)
                    cur.execute("""
                        INSERT INTO users (username, password_hash, account_no, account_name, balance)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING account_no;
                    """, (username, pwh, account_no, account_name, Decimal(initial_deposit)))

                    if Decimal(initial_deposit) > 0:
                        cur.execute("""
                            INSERT INTO transactions (account_no, amount, txn_type, counterparty)
                            VALUES (%s, %s, 'deposit', %s);
                        """, (account_no, Decimal(initial_deposit), "Initial"))

                    self.conn.commit()
                    return account_no
            except psycopg2.Error as e:
                self.conn.rollback()
                code = getattr(e, "pgcode", "")
                if code == "40001" and retries > 0:
                    retries -= 1
                    time.sleep(0.3)
                    continue
                raise

    def authenticate(self, username: str, password: str):
        with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SET DATABASE = banking;")
            cur.execute("""
                SELECT id, username, password_hash, account_no, account_name, balance
                FROM users WHERE username=%s;
            """, (username,))
            row = cur.fetchone()
            if not row:
                return None
            if not verify_password(password, row["password_hash"]):
                return None
            return {
                "id": row["id"],
                "username": row["username"],
                "account_no": row["account_no"],
                "account_name": row["account_name"],
                "balance": Decimal(row["balance"])
            }

    def get_balance(self, account_no: str) -> Decimal:
        with self.conn.cursor() as cur:
            cur.execute("SET DATABASE = banking;")
            cur.execute("SELECT balance FROM users WHERE account_no=%s;", (account_no,))
            r = cur.fetchone()
            return Decimal(r[0]) if r else Decimal("0")

    def get_last_transactions(self, account_no: str, limit: int = 5):
        with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SET DATABASE = banking;")
            cur.execute("""
                SELECT txn_type, amount, counterparty, created_at
                FROM transactions
                WHERE account_no=%s
                ORDER BY created_at DESC
                LIMIT %s;
            """, (account_no, limit))
            rows = cur.fetchall()
            return rows or []

    def transfer(self, from_acct: str, to_acct: str, amount: Decimal):
        amount = Decimal(amount)
        if amount <= 0:
            raise ValueError("Amount must be positive.")

        retries = 5
        while True:
            try:
                with self.conn.cursor() as cur:
                    cur.execute("SET DATABASE = banking;")
                    # Lock sender
                    cur.execute("SELECT balance FROM users WHERE account_no=%s FOR UPDATE;", (from_acct,))
                    row = cur.fetchone()
                    if not row:
                        raise ValueError("Sender account not found.")
                    from_bal = Decimal(row[0])

                    # Lock receiver
                    cur.execute("SELECT balance FROM users WHERE account_no=%s FOR UPDATE;", (to_acct,))
                    row2 = cur.fetchone()
                    if not row2:
                        raise ValueError("Recipient account not found.")

                    if from_bal < amount:
                        raise ValueError("Insufficient funds.")

                    cur.execute("UPDATE users SET balance = balance - %s WHERE account_no=%s;", (amount, from_acct))
                    cur.execute("UPDATE users SET balance = balance + %s WHERE account_no=%s;", (amount, to_acct))

                    cur.execute("""
                        INSERT INTO transactions (account_no, amount, txn_type, counterparty)
                        VALUES (%s, %s, 'transfer_out', %s);
                    """, (from_acct, amount, to_acct))
                    cur.execute("""
                        INSERT INTO transactions (account_no, amount, txn_type, counterparty)
                        VALUES (%s, %s, 'transfer_in', %s);
                    """, (to_acct, amount, from_acct))

                    self.conn.commit()
                    return
            except psycopg2.Error as e:
                self.conn.rollback()
                code = getattr(e, "pgcode", "")
                if code == "40001" and retries > 0:
                    retries -= 1
                    time.sleep(0.3)
                    continue
                raise
            except Exception:
                self.conn.rollback()
                raise


class BankingApp(tk.Tk):
    def __init__(self, db: DB):
        super().__init__()
        self.title("CockroachDB Banking (Distributed SQL Demo)")
        self.geometry("720x580")
        self.resizable(False, False)
        self.db = db
        self.current_user = None  # dict from authenticate

        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True, padx=12, pady=12)

        self.frames = {}
        for F in (LoginFrame, RegisterFrame, DashboardFrame):
            frame = F(parent=self.container, app=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginFrame")

    def show_frame(self, name):
        if name == "LoginFrame":
            lf = self.frames.get("LoginFrame")
            if lf and hasattr(lf, "clear_fields"):
                lf.clear_fields()
        frame = self.frames[name]
        frame.tkraise()
        if hasattr(frame, "on_show"):
            frame.on_show()

    def login(self, username: str, password: str):
        user = self.db.authenticate(username, password)
        if user is None:
            messagebox.showerror("Login Failed", "Invalid username or password.")
            return
        self.current_user = user
        self.show_frame("DashboardFrame")

    def logout(self):
        self.current_user = None
        lf = self.frames.get("LoginFrame")
        if lf and hasattr(lf, "clear_fields"):
            lf.clear_fields()
        self.show_frame("LoginFrame")

    def create_account(self, username: str, password: str, account_name: str, initial_deposit: str):
        try:
            amt = Decimal(initial_deposit or "0")
            acct_no = self.db.create_user(username, password, account_name, amt)
            messagebox.showinfo("Account Created", f"Account created!\nAccount No: {acct_no}")
            self.show_frame("LoginFrame")
        except psycopg2.Error as e:
            # Unique username / account name clash
            messagebox.showerror("Error", f"Database error: {e}")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def do_transfer(self, to_acct: str, amount: str):
        if not self.current_user:
            messagebox.showerror("Not logged in", "Please log in.")
            return
        try:
            amt = Decimal(amount)
            self.db.transfer(self.current_user["account_no"], to_acct.strip().upper(), amt)
            messagebox.showinfo("Success", f"Transferred {amt} to {to_acct}")
            # Refresh dashboard
            self.frames["DashboardFrame"].refresh()
        except Exception as ex:
            messagebox.showerror("Transfer Failed", str(ex))
    
    def show_admin_panel(self):
        """Show the admin panel"""
        password = tk.simpledialog.askstring("Admin Authentication", 
                                            "Enter admin password:", 
                                            show='*', 
                                            parent=self)

        # In a real application,  would verify this against a secure stored hash
        # For demo purposes, we're using a simple password check
        if password == "admin123":  # Change this to a more secure method in production
            # Create and show admin panel
            admin_window = AdminPanel(self, CONNECTION_STRING)
            admin_window.grab_set()  # Make the admin panel modal
        else:
            if password is not None:  # Only show error if user entered something
                messagebox.showerror("Access Denied", "Invalid admin password.")
class LoginFrame(ttk.Frame):
    def __init__(self, parent, app: BankingApp):
        super().__init__(parent)
        self.app = app

        title = ttk.Label(self, text="Login", font=("Segoe UI", 18, "bold"))
        title.pack(pady=10)

        form = ttk.Frame(self)
        form.pack(pady=10)

        ttk.Label(form, text="Username").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        ttk.Label(form, text="Password").grid(row=1, column=0, sticky="e", padx=5, pady=5)

        self.ent_user = ttk.Entry(form, width=32)
        self.ent_pass = ttk.Entry(form, show="*", width=32)

        self.ent_user.grid(row=0, column=1, padx=5, pady=5)
        self.ent_pass.grid(row=1, column=1, padx=5, pady=5)

        btns = ttk.Frame(self)
        btns.pack(pady=10)

        ttk.Button(btns, text="Login", command=self._login).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Create Account", 
                  command=lambda: self.app.show_frame("RegisterFrame")).grid(row=0, column=1, padx=6)
        
        # Add Admin button
        ttk.Button(btns, text="Admin", command=self.app.show_admin_panel).grid(row=0, column=2, padx=6)

    def _login(self):
        """Handle login button press"""
        username = self.ent_user.get().strip()
        password = self.ent_pass.get().strip()
        if not username or not password:
            messagebox.showerror("Missing Info", "Please enter both username and password.")
            return
        self.app.login(username, password)

    def clear_fields(self):
        """Clear input fields when returning to login"""
        self.ent_user.delete(0, tk.END)
        self.ent_pass.delete(0, tk.END)
class RegisterFrame(ttk.Frame):
    def __init__(self, parent, app: BankingApp):
        super().__init__(parent)
        self.app = app

        title = ttk.Label(self, text="Create Account", font=("Segoe UI", 18, "bold"))
        title.pack(pady=10)

        form = ttk.Frame(self)
        form.pack(pady=10)

        labels = ["Username", "Password", "Account Name", "Initial Deposit (optional)"]
        for i, label in enumerate(labels):
            ttk.Label(form, text=label).grid(row=i, column=0, sticky="e", padx=5, pady=6)

        self.ent_user = ttk.Entry(form, width=36)
        self.ent_pass = ttk.Entry(form, show="*", width=36)
        self.ent_acct_name = ttk.Entry(form, width=36)
        self.ent_init = ttk.Entry(form, width=36)

        self.ent_user.grid(row=0, column=1, padx=5, pady=6)
        self.ent_pass.grid(row=1, column=1, padx=5, pady=6)
        self.ent_acct_name.grid(row=2, column=1, padx=5, pady=6)
        self.ent_init.grid(row=3, column=1, padx=5, pady=6)

        ttk.Button(self, text="Create", command=self._create).pack(pady=12)
        ttk.Button(self, text="Back to Login", command=lambda: self.app.show_frame("LoginFrame")).pack()

    def _create(self):
        u = self.ent_user.get().strip()
        p = self.ent_pass.get()
        a = self.ent_acct_name.get().strip()
        init = self.ent_init.get().strip() or "0"
        if not u or not p or not a:
            messagebox.showerror("Missing Info", "Please fill username, password, and account name.")
            return
        self.app.create_account(u, p, a, init)

class DashboardFrame(ttk.Frame):
    def __init__(self, parent, app: BankingApp):
        super().__init__(parent)
        self.app = app

        self.lbl_title = ttk.Label(self, text="Dashboard", font=("Segoe UI", 18, "bold"))
        self.lbl_title.pack(pady=10)

        self.info = ttk.Label(self, text="", font=("Segoe UI", 11))
        self.info.pack()

        # Balance
        self.balance_var = tk.StringVar(value="Balance: -")
        ttk.Label(self, textvariable=self.balance_var, font=("Segoe UI", 14, "bold")).pack(pady=8)

        # Transfer box
        box = ttk.LabelFrame(self, text="Transfer Money")
        box.pack(fill="x", padx=10, pady=8)
        row = ttk.Frame(box); row.pack(fill="x", padx=8, pady=6)
        ttk.Label(row, text="Recipient Account No").grid(row=0, column=0, sticky="e", padx=5)
        self.ent_to = ttk.Entry(row, width=28)
        self.ent_to.grid(row=0, column=1, padx=5)

        row2 = ttk.Frame(box); row2.pack(fill="x", padx=8, pady=6)
        ttk.Label(row2, text="Amount").grid(row=0, column=0, sticky="e", padx=5)
        self.ent_amt = ttk.Entry(row2, width=28)
        self.ent_amt.grid(row=0, column=1, padx=5)

        ttk.Button(box, text="Send", command=self._send).pack(pady=8)

        # Transactions
        self.txn_tree = ttk.Treeview(self, columns=("type", "amount", "cp", "date"), show="headings", height=8)
        for c, h in zip(("type", "amount", "cp", "date"), ("Type", "Amount", "Counterparty", "Date")):
            self.txn_tree.heading(c, text=h)
            self.txn_tree.column(c, width=150 if c != "date" else 220, anchor="center")
        self.txn_tree.pack(fill="both", expand=True, padx=10, pady=10)

        # Footer buttons
        btns = ttk.Frame(self)
        btns.pack(pady=6)
        ttk.Button(btns, text="Refresh", command=self.refresh).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Logout", command=self.app.logout).grid(row=0, column=1, padx=6)

    def on_show(self):
        self.refresh()

    def refresh(self):
        u = self.app.current_user
        if not u:
            return
        self.lbl_title.config(text=f"Welcome, {u['username']}")
        self.info.config(text=f"Account: {u['account_no']}  •  Name: {u['account_name']}")
        # Update balance
        bal = self.app.db.get_balance(u["account_no"])
        self.app.current_user["balance"] = bal
        self.balance_var.set(f"Balance: {bal}")

        # Load last 5 txns
        for row in self.txn_tree.get_children():
            self.txn_tree.delete(row)
        txns = self.app.db.get_last_transactions(u["account_no"], 5)
        for t in txns:
            when = t["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            self.txn_tree.insert("", "end", values=(t["txn_type"], str(t["amount"]), t.get("counterparty") or "", when))

    def _send(self):
        to = self.ent_to.get().strip().upper()
        amt = self.ent_amt.get().strip()
        if not to or not amt:
            messagebox.showerror("Missing Info", "Please enter recipient account number and amount.")
            return
        if to == self.app.current_user["account_no"]:
            messagebox.showerror("Invalid", "Cannot transfer to your own account.")
            return
        self.app.do_transfer(to, amt)
        self.ent_to.delete(0, tk.END)
        self.ent_amt.delete(0, tk.END)



# ADMIN PANEL
class AdminPanel(tk.Toplevel):
    def __init__(self, parent, db_connection_string):
        super().__init__(parent)
        self.title("Banking System - Admin Panel")
        self.geometry("1000x700")
        self.resizable(True, True)
        
        # Database connection
        self.db_conn_str = db_connection_string
        self.conn = None
        self.connect_db()
        
        # Setup UI
        self.setup_ui()
        
        # Load initial data
        self.refresh_data()
        
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def connect_db(self):
        """Establish database connection"""
        try:
            self.conn = psycopg2.connect(self.db_conn_str)
            self.conn.set_session(autocommit=True)
        except Exception as e:
            messagebox.showerror("Database Error", f"Could not connect to database: {e}")
            self.destroy()
    
    def setup_ui(self):
        """Setup the admin panel UI"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Accounts tab
        self.accounts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.accounts_frame, text="Accounts")
        self.setup_accounts_tab()
        
        # Transactions tab
        self.transactions_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.transactions_frame, text="Transactions")
        self.setup_transactions_tab()
        
        # System tab
        self.system_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.system_frame, text="System")
        self.setup_system_tab()
        
    def setup_accounts_tab(self):
        """Setup accounts management tab"""
        # Search frame
        search_frame = ttk.Frame(self.accounts_frame)
        search_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=5, pady=5)
        self.account_search_var = tk.StringVar()
        self.account_search_entry = ttk.Entry(search_frame, textvariable=self.account_search_var, width=30)
        self.account_search_entry.grid(row=0, column=1, padx=5, pady=5)
        self.account_search_entry.bind("<KeyRelease>", self.filter_accounts)
        
        ttk.Button(search_frame, text="Refresh", command=self.refresh_accounts).grid(row=0, column=2, padx=5, pady=5)
        
        # Accounts treeview
        columns = ("id", "username", "account_no", "account_name", "balance", "created_at")
        self.accounts_tree = ttk.Treeview(self.accounts_frame, columns=columns, show="headings", height=20)
        
        # Define headings
        self.accounts_tree.heading("id", text="ID")
        self.accounts_tree.heading("username", text="Username")
        self.accounts_tree.heading("account_no", text="Account No")
        self.accounts_tree.heading("account_name", text="Account Name")
        self.accounts_tree.heading("balance", text="Balance")
        self.accounts_tree.heading("created_at", text="Created At")
        
        # Define columns
        self.accounts_tree.column("id", width=50, anchor="center")
        self.accounts_tree.column("username", width=120, anchor="w")
        self.accounts_tree.column("account_no", width=100, anchor="center")
        self.accounts_tree.column("account_name", width=150, anchor="w")
        self.accounts_tree.column("balance", width=100, anchor="e")
        self.accounts_tree.column("created_at", width=150, anchor="center")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.accounts_frame, orient=tk.VERTICAL, command=self.accounts_tree.yview)
        self.accounts_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.accounts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)
        
        # Context menu for accounts
        self.accounts_menu = tk.Menu(self, tearoff=0)
        self.accounts_menu.add_command(label="View Transactions", command=self.view_account_transactions)
        self.accounts_menu.add_command(label="Reset Password", command=self.reset_password)
        self.accounts_menu.add_separator()
        self.accounts_menu.add_command(label="Refresh", command=self.refresh_accounts)
        
        self.accounts_tree.bind("<Button-3>", self.show_accounts_context_menu)
        
    def setup_transactions_tab(self):
        """Setup transactions monitoring tab"""
        # Filter frame
        filter_frame = ttk.Frame(self.transactions_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(filter_frame, text="Account No:").grid(row=0, column=0, padx=5, pady=5)
        self.txn_account_var = tk.StringVar()
        self.txn_account_entry = ttk.Entry(filter_frame, textvariable=self.txn_account_var, width=15)
        self.txn_account_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Type:").grid(row=0, column=2, padx=5, pady=5)
        self.txn_type_var = tk.StringVar(value="All")
        txn_types = ["All", "deposit", "withdrawal", "transfer_in", "transfer_out"]
        self.txn_type_combo = ttk.Combobox(filter_frame, textvariable=self.txn_type_var, values=txn_types, state="readonly", width=12)
        self.txn_type_combo.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Date From:").grid(row=0, column=4, padx=5, pady=5)
        self.date_from_var = tk.StringVar()
        self.date_from_entry = ttk.Entry(filter_frame, textvariable=self.date_from_var, width=12)
        self.date_from_entry.grid(row=0, column=5, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Date To:").grid(row=0, column=6, padx=5, pady=5)
        self.date_to_var = tk.StringVar()
        self.date_to_entry = ttk.Entry(filter_frame, textvariable=self.date_to_var, width=12)
        self.date_to_entry.grid(row=0, column=7, padx=5, pady=5)
        
        ttk.Button(filter_frame, text="Apply Filters", command=self.filter_transactions).grid(row=0, column=8, padx=5, pady=5)
        ttk.Button(filter_frame, text="Clear Filters", command=self.clear_transaction_filters).grid(row=0, column=9, padx=5, pady=5)
        
        # Transactions treeview
        columns = ("id", "account_no", "amount", "txn_type", "counterparty", "created_at")
        self.transactions_tree = ttk.Treeview(self.transactions_frame, columns=columns, show="headings", height=20)
        
        # Define headings
        self.transactions_tree.heading("id", text="ID")
        self.transactions_tree.heading("account_no", text="Account No")
        self.transactions_tree.heading("amount", text="Amount")
        self.transactions_tree.heading("txn_type", text="Type")
        self.transactions_tree.heading("counterparty", text="Counterparty")
        self.transactions_tree.heading("created_at", text="Date/Time")
        
        # Define columns
        self.transactions_tree.column("id", width=50, anchor="center")
        self.transactions_tree.column("account_no", width=100, anchor="center")
        self.transactions_tree.column("amount", width=100, anchor="e")
        self.transactions_tree.column("txn_type", width=100, anchor="center")
        self.transactions_tree.column("counterparty", width=120, anchor="w")
        self.transactions_tree.column("created_at", width=150, anchor="center")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.transactions_frame, orient=tk.VERTICAL, command=self.transactions_tree.yview)
        self.transactions_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.transactions_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)
        
    def setup_system_tab(self):
        """Setup system management tab"""
        # Stats frame
        stats_frame = ttk.LabelFrame(self.system_frame, text="System Statistics")
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Stats labels
        stats_data = [
            ("Total Accounts", "total_accounts"),
            ("Total Balance", "total_balance"),
            ("Total Transactions", "total_transactions"),
            ("Largest Account", "largest_account"),
            ("Last Transaction", "last_transaction")
        ]
        
        self.stats_vars = {}
        for i, (label, key) in enumerate(stats_data):
            ttk.Label(stats_frame, text=label + ":").grid(row=i, column=0, sticky="w", padx=5, pady=2)
            self.stats_vars[key] = tk.StringVar(value="Loading...")
            ttk.Label(stats_frame, textvariable=self.stats_vars[key]).grid(row=i, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Button(stats_frame, text="Refresh Stats", command=self.update_stats).grid(row=0, column=2, rowspan=5, padx=20, pady=5)
        
        # Admin actions frame
        actions_frame = ttk.LabelFrame(self.system_frame, text="Administrative Actions")
        actions_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(actions_frame, text="Create Test Data", command=self.create_test_data).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(actions_frame, text="Database Maintenance", command=self.db_maintenance).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(actions_frame, text="Export Data", command=self.export_data).grid(row=0, column=2, padx=5, pady=5)
        
    def refresh_data(self):
        """Refresh all data in the admin panel"""
        self.refresh_accounts()
        self.refresh_transactions()
        self.update_stats()
        
    def refresh_accounts(self):
        """Refresh accounts list"""
        try:
            # Clear existing data
            for item in self.accounts_tree.get_children():
                self.accounts_tree.delete(item)
                
            # Fetch accounts from database
            with self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SET DATABASE = banking;")
                cur.execute("""
                    SELECT id, username, account_no, account_name, balance, created_at 
                    FROM users 
                    ORDER BY created_at DESC
                """)
                
                for row in cur:
                    self.accounts_tree.insert("", "end", values=(
                        row['id'],
                        row['username'],
                        row['account_no'],
                        row['account_name'],
                        f"${row['balance']:,.2f}",
                        row['created_at'].strftime("%Y-%m-%d %H:%M")
                    ))
                    
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to load accounts: {e}")
    
    def filter_accounts(self, event=None):
        """Filter accounts based on search text"""
        search_text = self.account_search_var.get().lower()
        
        # Show all items if search is empty
        if not search_text:
            for item in self.accounts_tree.get_children():
                self.accounts_tree.item(item, tags=())
            return
            
        # Hide non-matching items
        for item in self.accounts_tree.get_children():
            values = self.accounts_tree.item(item, 'values')
            if any(search_text in str(value).lower() for value in values):
                self.accounts_tree.item(item, tags=())
            else:
                self.accounts_tree.item(item, tags=('hidden',))
                
        # Hide items with hidden tag
        self.accounts_tree.tag_configure('hidden', display=False)
    
    def refresh_transactions(self):
        """Refresh transactions list"""
        try:
            # Clear existing data
            for item in self.transactions_tree.get_children():
                self.transactions_tree.delete(item)
                
            # Fetch transactions from database
            with self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SET DATABASE = banking;")
                cur.execute("""
                    SELECT id, account_no, amount, txn_type, counterparty, created_at 
                    FROM transactions 
                    ORDER BY created_at DESC
                    LIMIT 500
                """)
                
                for row in cur:
                    self.transactions_tree.insert("", "end", values=(
                        row['id'],
                        row['account_no'],
                        f"${row['amount']:,.2f}",
                        row['txn_type'],
                        row['counterparty'] or "",
                        row['created_at'].strftime("%Y-%m-%d %H:%M")
                    ))
                    
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to load transactions: {e}")
    
    def filter_transactions(self):
        """Apply filters to transactions"""
        try:
            # Clear existing data
            for item in self.transactions_tree.get_children():
                self.transactions_tree.delete(item)
                
            # Build query
            query = """
                SELECT id, account_no, amount, txn_type, counterparty, created_at 
                FROM transactions 
                WHERE 1=1
            """
            params = []
            
            # Account filter
            account_no = self.txn_account_var.get().strip()
            if account_no:
                query += " AND account_no = %s"
                params.append(account_no)
                
            # Type filter
            txn_type = self.txn_type_var.get()
            if txn_type != "All":
                query += " AND txn_type = %s"
                params.append(txn_type)
                
            # Date filters
            date_from = self.date_from_var.get().strip()
            if date_from:
                query += " AND created_at >= %s"
                params.append(date_from)
                
            date_to = self.date_to_var.get().strip()
            if date_to:
                query += " AND created_at <= %s"
                params.append(date_to)
                
            query += " ORDER BY created_at DESC LIMIT 500"
            
            # Execute query
            with self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SET DATABASE = banking;")
                cur.execute(query, params)
                
                for row in cur:
                    self.transactions_tree.insert("", "end", values=(
                        row['id'],
                        row['account_no'],
                        f"${row['amount']:,.2f}",
                        row['txn_type'],
                        row['counterparty'] or "",
                        row['created_at'].strftime("%Y-%m-%d %H:%M")
                    ))
                    
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to filter transactions: {e}")
    
    def clear_transaction_filters(self):
        """Clear all transaction filters"""
        self.txn_account_var.set("")
        self.txn_type_var.set("All")
        self.date_from_var.set("")
        self.date_to_var.set("")
        self.refresh_transactions()
    
    def update_stats(self):
        """Update system statistics"""
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SET DATABASE = banking;")
                
                # Total accounts
                cur.execute("SELECT COUNT(*) as count FROM users")
                total_accounts = cur.fetchone()['count']
                self.stats_vars['total_accounts'].set(str(total_accounts))
                
                # Total balance
                cur.execute("SELECT SUM(balance) as total FROM users")
                total_balance = cur.fetchone()['total'] or 0
                self.stats_vars['total_balance'].set(f"${total_balance:,.2f}")
                
                # Total transactions
                cur.execute("SELECT COUNT(*) as count FROM transactions")
                total_transactions = cur.fetchone()['count']
                self.stats_vars['total_transactions'].set(str(total_transactions))
                
                # Largest account
                cur.execute("SELECT account_name, balance FROM users ORDER BY balance DESC LIMIT 1")
                largest = cur.fetchone()
                if largest:
                    self.stats_vars['largest_account'].set(
                        f"{largest['account_name']} (${largest['balance']:,.2f})"
                    )
                else:
                    self.stats_vars['largest_account'].set("N/A")
                
                # Last transaction
                cur.execute("SELECT created_at FROM transactions ORDER BY created_at DESC LIMIT 1")
                last_txn = cur.fetchone()
                if last_txn:
                    self.stats_vars['last_transaction'].set(
                        last_txn['created_at'].strftime("%Y-%m-%d %H:%M")
                    )
                else:
                    self.stats_vars['last_transaction'].set("N/A")
                    
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to update statistics: {e}")
    
    def view_account_transactions(self):
        """View transactions for selected account"""
        selection = self.accounts_tree.selection()
        if not selection:
            messagebox.showwarning("Selection Required", "Please select an account first.")
            return
            
        item = self.accounts_tree.item(selection[0])
        account_no = item['values'][2]  # Account number is at index 2
        
        # Switch to transactions tab and filter by account
        self.notebook.select(1)  # Switch to transactions tab
        self.txn_account_var.set(account_no)
        self.filter_transactions()
    
    def reset_password(self):
        """Reset password for selected account"""
        selection = self.accounts_tree.selection()
        if not selection:
            messagebox.showwarning("Selection Required", "Please select an account first.")
            return
            
        item = self.accounts_tree.item(selection[0])
        username = item['values'][1]  # Username is at index 1
        account_no = item['values'][2]  # Account number is at index 2
        
        # Generate a random password
        import random, string
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        
        # Hash the new password
        from hashlib import pbkdf2_hmac
        import binascii
        salt = os.urandom(16)
        dk = pbkdf2_hmac('sha256', new_password.encode(), salt, 100000)
        hashed = binascii.hexlify(salt).decode() + "$" + binascii.hexlify(dk).decode()
        
        try:
            # Update password in database
            with self.conn.cursor() as cur:
                cur.execute("SET DATABASE = banking;")
                cur.execute(
                    "UPDATE users SET password_hash = %s WHERE username = %s",
                    (hashed, username)
                )
            
            # Show the new password to admin
            messagebox.showinfo(
                "Password Reset", 
                f"Password for account {account_no} has been reset.\n\n"
                f"New password: {new_password}\n\n"
                "Please inform the user to change their password after login."
            )
            
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to reset password: {e}")
    
    def show_accounts_context_menu(self, event):
        """Show context menu for accounts tree"""
        item = self.accounts_tree.identify_row(event.y)
        if item:
            self.accounts_tree.selection_set(item)
            self.accounts_menu.post(event.x_root, event.y_root)
    
    def create_test_data(self):
        """Create test data for demonstration"""
        if not messagebox.askyesno(
            "Confirm", 
            "This will create test accounts and transactions. Continue?"
        ):
            return
            
        try:
            with self.conn.cursor() as cur:
                cur.execute("SET DATABASE = banking;")
                
                # Create test accounts if they don't exist
                test_accounts = [
                    ("test_user1", "Test User 1", "100001", 5000.00),
                    ("test_user2", "Test User 2", "100002", 3000.00),
                    ("test_user3", "Test User 3", "100003", 7500.00)
                ]
                
                for username, account_name, account_no, balance in test_accounts:
                    # Check if account exists
                    cur.execute("SELECT 1 FROM users WHERE account_no = %s", (account_no,))
                    if not cur.fetchone():
                        # Create account with hashed password "test123"
                        salt = os.urandom(16)
                        dk = pbkdf2_hmac('sha256', "test123".encode(), salt, 100000)
                        hashed = binascii.hexlify(salt).decode() + "$" + binascii.hexlify(dk).decode()
                        
                        cur.execute(
                            "INSERT INTO users (username, password_hash, account_no, account_name, balance) "
                            "VALUES (%s, %s, %s, %s, %s)",
                            (username, hashed, account_no, account_name, balance)
                        )
                
                # Create some test transactions
                from datetime import datetime, timedelta
                now = datetime.now()
                
                for i in range(20):
                    amount = round(random.uniform(10, 500), 2)
                    days_ago = random.randint(0, 30)
                    created_at = now - timedelta(days=days_ago)
                    
                    # Randomly select transaction type and accounts
                    txn_type = random.choice(["deposit", "withdrawal", "transfer_out"])
                    
                    if txn_type == "transfer_out":
                        from_account = "100001"
                        to_account = random.choice(["100002", "100003"])
                        counterparty = to_account
                        
                        # Insert transfer out
                        cur.execute(
                            "INSERT INTO transactions (account_no, amount, txn_type, counterparty, created_at) "
                            "VALUES (%s, %s, 'transfer_out', %s, %s)",
                            (from_account, amount, to_account, created_at)
                        )
                        
                        # Insert transfer in
                        cur.execute(
                            "INSERT INTO transactions (account_no, amount, txn_type, counterparty, created_at) "
                            "VALUES (%s, %s, 'transfer_in', %s, %s)",
                            (to_account, amount, from_account, created_at)
                        )
                    else:
                        account = random.choice(["100001", "100002", "100003"])
                        cur.execute(
                            "INSERT INTO transactions (account_no, amount, txn_type, created_at) "
                            "VALUES (%s, %s, %s, %s)",
                            (account, amount, txn_type, created_at)
                        )
                
                messagebox.showinfo("Success", "Test data created successfully.")
                self.refresh_data()
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create test data: {e}")
    
    def db_maintenance(self):
        """Perform database maintenance tasks"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("SET DATABASE = banking;")
                
                # Reindex tables
                for table in ["users", "transactions"]:
                    cur.execute(f"REINDEX TABLE {table}")
                
                # Vacuum analyze
                cur.execute("VACUUM ANALYZE")
                
            messagebox.showinfo("Success", "Database maintenance completed.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Maintenance failed: {e}")
    
    def export_data(self):
        """Export data to CSV file"""
        from tkinter import filedialog
        import csv
        
        # Ask for file location
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not filename:
            return
            
        try:
            # Get current tab to determine what to export
            current_tab = self.notebook.index(self.notebook.select())
            
            if current_tab == 0:  # Accounts tab
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["ID", "Username", "Account No", "Account Name", "Balance", "Created At"])
                    
                    for item in self.accounts_tree.get_children():
                        values = self.accounts_tree.item(item, 'values')
                        writer.writerow(values)
                        
            elif current_tab == 1:  # Transactions tab
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["ID", "Account No", "Amount", "Type", "Counterparty", "Date/Time"])
                    
                    for item in self.transactions_tree.get_children():
                        values = self.transactions_tree.item(item, 'values')
                        writer.writerow(values)
            
            messagebox.showinfo("Success", f"Data exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")
    
    def on_close(self):
        """Handle window close event"""
        if self.conn:
            self.conn.close()
        self.destroy()



# Add this method to BankingApp class to launch the admin panel
def show_admin_panel(self):
    """Show the admin panel (add this method to your BankingApp class)"""
    # might want to add authentication for the admin panel
    # For simplicity, we'll just ask for a password here
    password = tk.simpledialog.askstring("Admin Authentication", "Enter admin password:", show='*')
    
    # In a real application, you would verify this against a stored admin password
    if password == "admin123":  # Change this to a secure password in production
        AdminPanel(self, CONNECTION_STRING)
    else:
        messagebox.showerror("Access Denied", "Invalid admin password.")



def main():
    try:
        db = DB(CONNECTION_STRING)
    except Exception as e:
        messagebox.showerror("DB Connection Failed", f"Could not connect to CockroachDB.\n\n{e}")
        return
    app = BankingApp(db)
    app.mainloop()
    db.close()

if __name__ == "__main__":
    main()