import os
import re
import sqlite3

from flask import Flask, flash, redirect, render_template, url_for, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response




@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    with sqlite3.connect('finance.db') as connection:
        db = connection.cursor()
        db.execute("SELECT cash FROM users WHERE id=?", (session["user_id"], ))
        cash = db.fetchone()
        db.execute(
        "SELECT symbol, SUM(shares) AS sumShares, SUM(amount) AS sumAmount FROM transactions WHERE user_id=? GROUP BY symbol HAVING sumShares>0", (session["user_id"], ))
        stocksOrigin = db.fetchall() # Original data structure: tuples in list
        key = [column[0] for column in db.description] # Get the keys
        stocks = [] # New data structure: dicts in list
        for i in range(len(stocksOrigin)):
            stocks.append(dict(zip(key, stocksOrigin[i]))) # Convert tuples into dicts

    currentCash = cash[0]
    totalProperty = currentCash

    for stock in stocks:
        quote = lookup(stock['symbol'])
        stock["price"] = quote['price']  # Current stock price
        # Store formated values for display purpose
        stock["priceFormated"] = f"{stock['price']:,.2f}"
        stock["stockAmount"] = f"{stock['sumShares'] * stock['price']:,.2f}"
        totalProperty += stock['sumShares'] * stock['price']

    return render_template("index.html", stocks=stocks, cash=f"{currentCash:,.2f}", totalProperty=f"{totalProperty:,.2f}")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        if type(shares) == float:
            return apology("Invalid number of shares", 400)

        try:
            shares = int(shares)

        except ValueError:
            return apology("Invalid number of shares.", 400)

        if shares <= 0:
            return apology("Number of shares should be positive.", 400)

        quote = lookup(symbol)
        if not quote:
            return apology("Invalid symbol.", 400)

        price = quote['price']
        totalAmount = round(price * shares, 2)
        user_id = session["user_id"]

        with sqlite3.connect('finance.db') as connection:
            db = connection.cursor()
            db.execute("SELECT CASH FROM users WHERE id=?", (user_id, ))
            cash = db.fetchone()

            # Update the datbase if transaction is successful
            if cash[0] >= totalAmount:
                #print(cash[0], totalAmount)
                newCash = cash[0] - totalAmount
                db.execute("UPDATE users SET cash = ? WHERE id = ?", (newCash, session["user_id"], ))
                db.execute("INSERT INTO transactions (user_id, symbol, shares, amount) VALUES (?, ?, ?, ?)",
                        (user_id, symbol, shares, totalAmount, ))
                flash("Transaction Successful!")
                return redirect(url_for('index'))
            else:
                return apology("Transaction Failed. (Not Enough Money)")

    else:
        return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    with sqlite3.connect('finance.db') as connection:
        db = connection.cursor()
        db.execute(
            "SELECT * FROM transactions WHERE user_id=? ORDER BY transacted DESC", (user_id, ))
        transactionsOrigin = db.fetchall()  # Original data structure: tuples in list
        key = [column[0] for column in db.description]  # Get the key
        transactions = []  # New data structure: dicts in list
        for i in range(len(transactionsOrigin)):
            transactions.append(dict(zip(key, transactionsOrigin[i])))  # # Convert tuples into dicts

        for transaction in transactions:
            transaction["amount"] = f"{transaction['amount']:,.2f}"

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        
        # Query database for username
        with sqlite3.connect('finance.db') as connection:
            db = connection.cursor()
            db.execute(
                "SELECT * FROM users WHERE username = ?", (request.form.get("username"), )
            )
            rows = db.fetchone()

        # Ensure username exists and password is correct
        if not rows or not check_password_hash(
            rows[2], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid symbol", 400)
        else:
            return render_template("quoted.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    reservedNameList = ['about', 'admin', 'administrator', 'app', 'undefined', 'login', 'name']

    with sqlite3.connect('finance.db') as connection:
        db = connection.cursor()
        db.execute("SELECT username FROM users")
        users = db.fetchall()
        userList = []
        for user in users:
            userList.append(user[0])

        if request.method == "POST":
            username = request.form.get("username", "").strip()  # Prevent empty string

            if not re.match(r'^[A-Za-z0-9-_]{3,15}$', username):
                return apology('Valid username should only contains letters, numbers, hyphen(-) and underscore(_).'
                            ' The length should be at least 3 characters and no longer than 15 characters.', 400)

            if username in userList:
                return apology('Username already exists', 400)

            if username.lower() in reservedNameList:
                return apology('This username is reserved by administrator. Please choose another one.', 400)

            db.execute("SELECT * FROM users WHERE username = ?", (username,))
            rows = db.fetchall()
            if rows:
                return apology("Username already exists.", 400)

            password = request.form.get("password")

            if not password:
                return apology("Valid password is required.", 400)

            # Refuse too short or too long password
            if len(password) < 8 or len(password) > 20:
                return apology('A valid password length should be at least 8 characters and no longer than 20 characters.', 400)

            if request.form.get("password") != request.form.get("confirmation"):
                return apology('The passwords entered doesn\'t match.', 400)

            hash = generate_password_hash(password)

            db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", (username, hash,))

            # Query database for username
            db.execute(
                "SELECT * FROM users WHERE username = ?", (request.form.get("username"), )
            )
            rows = db.fetchall()

            flash("Registration Success!")
            # Remember which user has logged in
            session["user_id"] = rows[0][0]

            # Redirect user to home page
            return redirect("/")

        else:
            return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    with sqlite3.connect('finance.db') as connection:
        db = connection.cursor()

        db.execute(
            "SELECT symbol, SUM(shares) AS sumShares, SUM(amount) AS sumAmount FROM transactions WHERE user_id=? GROUP BY symbol HAVING sumShares>0", (session["user_id"], ))
        stocksOrigin = db.fetchall()  # Original data structure: tuples in list
        key = [column[0] for column in db.description]  # Get the key
        stocks = []  # New data structure: dicts in list
        for i in range(len(stocksOrigin)):
            stocks.append(dict(zip(key, stocksOrigin[i])))  # Convert tuples into dicts

        if request.method == "POST":
            symbol = request.form.get("symbol")
            shares = request.form.get("shares")

            try:
                shares = int(shares)
            except ValueError:
                return apology("Invalid number of shares.", 400)

            if shares <= 0:
                return apology("Shares' number should be positive.", 400)

            user_id = session["user_id"]

            if not symbol:
                return apology("Invalid Symbol", 400)

            for stock in stocks:
                if stock["symbol"] == symbol:
                    if stock["sumShares"] >= shares:
                        quote = lookup(symbol)
                        if not quote:
                            return apology("Server connection failed， please try later.")
                        totalAmount = quote["price"] * shares

                        with sqlite3.connect('finance.db') as connection:
                            db = connection.cursor()
                            db.execute("SELECT cash FROM users WHERE id=?", (user_id, ))
                            cash = db.fetchone()


                            currentCash = cash[0] + totalAmount

                            # Update the database
                            db.execute("INSERT INTO transactions (user_id, symbol, shares, amount) VALUES (?, ?, ?, ?)",
                                    (user_id, symbol, -shares, totalAmount, ))
                            db.execute("UPDATE users SET cash=? WHERE id=?", (currentCash, user_id, ))

                            # Message for user
                            flash("Transaction successful!")
                            return redirect(url_for('index'))

                    else:
                        return apology("Not enough shares.")

    return render_template("sell.html", stocks=stocks)
