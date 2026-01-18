CURRENCIES = {
    "KES": {"symbol": "KES", "rate": 130, "decimals": 0},
    "USD": {"symbol": "$", "rate": 1, "decimals": 2},
    "EUR": {"symbol": "€", "rate": 0.93, "decimals": 2},
    "CDF": {"symbol": "CDF", "rate": 2500, "decimals": 0},
    "TZS": {"symbol": "TZS", "rate": 2700, "decimals": 0},
    "UGX": {"symbol": "UGX", "rate": 3700, "decimals": 0},
}

from flask import jsonify, request
from email.mime import image
from models import Video, VideoLike
from flask import abort, session, g
import time  
import os
from flask import (
    Flask, render_template, redirect,
    url_for, request, flash, session, jsonify
)
from flask_login import (
    login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_

from config import Config
from extensions import db, migrate, bcrypt, login_manager
from models import User, Category, Product, ProductImage, Order, OrderItem, Notification, ChatMessage, Video, db, Banner, BannerImage
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
# =========================
# UPLOAD FOLDERS CONFIG
# =========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
PRODUCT_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "products")
CATEGORY_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "categories")

os.makedirs(PRODUCT_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CATEGORY_UPLOAD_FOLDER, exist_ok=True)


# =========================
# APP SETUP
# =========================
app = Flask(__name__)
@app.template_filter("kes")
def kes_filter(amount):
    if amount is None:
        return "KES 0"
    return f"KES {amount:,.0f}"
app.secret_key = "dev-secret-key-change-later"
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)
# =========================
# LANGUAGE CONFIG
# =========================
SUPPORTED_LANGUAGES = ["en", "fr"]

@app.before_request
def set_language():
    g.lang = session.get("lang", "en")



# ===============================
# UPLOADS
# ===============================
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

# ===============================
# CORE CONFIG
# ===============================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app.config.from_object(Config)

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. Postgres is required in production.")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL.replace(
    "postgres://", "postgresql://"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# ===============================
# SECURITY
# ===============================
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")

# ===============================
# EMAIL
# ===============================
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "guzones.app@gmail.com")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "opfgzxjjuspadxbi")
app.config["MAIL_DEFAULT_SENDER"] = "Guzones <guzones.app@gmail.com>"

    
# =========================
# EXTENSIONS
# =========================
db.init_app(app)
migrate.init_app(app, db)
bcrypt.init_app(app)
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =========================
# HELPERS
# =========================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_cart():
    return session.get("cart", {})


def save_cart(cart):
    session["cart"] = cart
    session.modified = True


@app.context_processor
def cart_count():
    cart = session.get("cart", {})
    count = sum(item.get("quantity", 0) for item in cart.values())
    return dict(cart_count=count)


# =========================
# HOME
# =========================
@app.route("/")
def home():

    banners = Banner.query.filter_by(is_active=True).all()
    products = Product.query.all()

    categories = Category.query.all()

    new_arrivals = Product.query.filter_by(is_new=True) \
        .order_by(Product.created_at.desc()).limit(8).all()

    trending = Product.query.filter_by(is_trending=True) \
        .order_by(Product.created_at.desc()).limit(8).all()

    on_sale = Product.query.filter_by(is_on_sale=True) \
        .order_by(Product.created_at.desc()).limit(8).all()

    # FEATURED (For You)
    featured = Product.query.filter_by(is_featured=True) \
        .order_by(Product.created_at.desc()).limit(12).all()

    # FALLBACK: if no featured, show latest products
    if not featured:
        featured = Product.query.order_by(Product.created_at.desc()).limit(12).all()

    return render_template(
        "home.html",
        banners=banners,
        categories=categories,
        new_arrivals=new_arrivals,
        trending=trending,
        on_sale=on_sale,
        products=featured
    )

@app.route("/banner/<int:banner_id>")
def banner_detail(banner_id):
    banner = Banner.query.get_or_404(banner_id)
    return render_template("banner_detail.html", banner=banner)

# =========================
# PRODUCTS
# =========================
@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)

    related_products = Product.query.filter(
        Product.category_id == product.category_id,
        Product.id != product.id
    ).limit(4).all()

    return render_template(
        "product_detail.html",
        product=product,
        related_products=related_products
    )


@app.route("/category/<int:category_id>")
def products_by_category(category_id):
    page = request.args.get("page", 1, type=int)
    per_page = 12

    category = Category.query.get_or_404(category_id)

    pagination = Product.query.filter_by(category_id=category_id)\
        .order_by(Product.id.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)

    products = pagination.items

    # 🔹 AJAX (Infinite scroll)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        if not products:
            return ""   # 🔥 THIS STOPS FAKE SCROLLING
        return render_template(
            "partials/_category_products.html",
            products=products
        )

    # 🔹 Normal page load
    return render_template(
        "category_products.html",
        category=category,
        products=products
    )

# =========================
# SEARCH API
# =========================
@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)

    query = Product.query
    if q:
        query = query.filter(
            or_(
                Product.name_en.ilike(f"%{q}%"),
                Product.description_en.ilike(f"%{q}%")
            )
        )

    pagination = query.order_by(Product.created_at.desc())\
        .paginate(page=page, per_page=8, error_out=False)

    results = []
    for p in pagination.items:
        image = p.images[0].image if p.images else None
        results.append({
            "id": p.id,
            "name": p.name_fr if g.lang == "fr" else p.name_en,
            "price": money(p),
            "image": image
        })

    return jsonify({
        "products": results,
        "has_next": pagination.has_next
    })


# =========================
# CART
# =========================
@app.route("/add-to-cart/<int:product_id>")
def add_to_cart(product_id):
    if not current_user.is_authenticated:
        flash("Please login first", "warning")
        return redirect(url_for("signup", next=request.path))

    product = Product.query.get_or_404(product_id)
    cart = get_cart()
    pid = str(product_id)

    if pid in cart:
        cart[pid]["quantity"] += 1
    else:
        cart[pid] = {
            "quantity": 1,
            "price": float(product.price),
            "name": product.name_en
        }

    save_cart(cart)
    flash("Added to cart", "success")
    return redirect(request.referrer or url_for("home"))


@app.route("/cart")
def cart():
    cart = get_cart()
    items = []
    total_usd = 0.0  # 🔑 ALWAYS USD

    for pid, item in cart.items():
        product = Product.query.get(int(pid))
        if not product:
            continue

        subtotal_usd = product.price * item["quantity"]
        total_usd += subtotal_usd

        items.append({
            "product": product,
            "quantity": item["quantity"],
            "subtotal_usd": subtotal_usd
        })

    return render_template(
        "cart.html",
        items=items,
        total_usd=total_usd
    )
# =========================
# CART ACTIONS
# =========================
@app.route("/cart/increase/<int:product_id>")
def cart_increase(product_id):
    cart = get_cart()
    pid = str(product_id)

    if pid in cart:
        cart[pid]["quantity"] += 1

    save_cart(cart)
    return redirect(url_for("cart"))


@app.route("/cart/decrease/<int:product_id>")
def cart_decrease(product_id):
    cart = get_cart()
    pid = str(product_id)

    if pid in cart:
        cart[pid]["quantity"] -= 1
        if cart[pid]["quantity"] <= 0:
            del cart[pid]

    save_cart(cart)
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:product_id>")
def cart_remove(product_id):
    cart = get_cart()
    pid = str(product_id)

    if pid in cart:
        del cart[pid]

    save_cart(cart)
    return redirect(url_for("cart"))
# =========================
# CHECKOUT
# =========================
@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    cart = get_cart()

    if not cart:
        flash("Your cart is empty", "warning")
        return redirect(url_for("cart"))

    items = []
    total = 0

    for pid, item in cart.items():
        product = Product.query.get(int(pid))
        if not product:
            continue

        subtotal = product.price * item["quantity"]
        total += subtotal

        items.append({
            "product": product,
            "quantity": item["quantity"],
            "subtotal": subtotal
        })

    if request.method == "POST":
        order = Order(
            user_id=current_user.id,
            total_amount=total,
            payment_status="unpaid",
            delivery_status="pending"
        )
        db.session.add(order)
        db.session.commit()

        for item in items:
            db.session.add(OrderItem(
                order_id=order.id,
                product_id=item["product"].id,
                quantity=item["quantity"],
                price=item["product"].price
            ))

        db.session.commit()
        session.pop("cart", None)

        flash("Order placed successfully", "success")
        return redirect(url_for("admin_orders") if current_user.role in ["admin", "superadmin"] else url_for("home"))

    return render_template("checkout.html", items=items, total=total)


# =========================
# AUTH
# =========================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    next_page = request.args.get("next")

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        whatsapp = request.form.get("full_phone")  # ✅ from intl-tel-input
        address = request.form.get("address", "").strip()
        password = request.form.get("password")

        # 🔴 Basic validation
        if not all([name, whatsapp, password]):
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for("signup"))

        # 🔴 Phone format sanity check
        if not whatsapp.startswith("+") or len(whatsapp) < 10:
            flash("Invalid WhatsApp number.", "danger")
            return redirect(url_for("signup"))

        # 🔴 Prevent duplicate WhatsApp numbers
        if User.query.filter_by(whatsapp=whatsapp).first():
            flash("An account with this WhatsApp number already exists.", "warning")
            return redirect(url_for("login"))

        # ✅ Create user
        user = User(
            name=name,
            whatsapp=whatsapp,
            address=address,
            password=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        # ✅ Auto login
        login_user(user)

        flash("Account created successfully 🎉", "success")
        return redirect(next_page or url_for("home"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    next_page = request.args.get("next")

    if request.method == "POST":
        whatsapp = request.form.get("full_phone")
        password = request.form.get("password")

        if not whatsapp or not password:
            flash("Please fill in all fields.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(whatsapp=whatsapp).first()

        if not user or not check_password_hash(user.password, password):
            flash("Invalid WhatsApp number or password.", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash("Welcome back 👋", "success")
        return redirect(next_page or url_for("home"))

    return render_template("login.html")

@app.context_processor
def inject_unread_messages():
    if current_user.is_authenticated:
        count = ChatMessage.query.filter_by(
            user_id=current_user.id,
            sender="admin",
            is_read=False
        ).count()
    else:
        count = 0

    return dict(unread_messages=count)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        user = User.query.filter_by(email=email).first()

        # Always show same message (security)
        if not user:
            flash("If that email exists, a reset link was sent.", "info")
            return redirect(url_for("login"))

        token = serializer.dumps(email, salt="password-reset")

        reset_link = url_for(
            "reset_password",
            token=token,
            _external=True
        )

        msg = Message(
            "Reset your Guzones password",
            recipients=[email]
        )

        msg.body = f"""
Hello,

Click the link below to reset your password:

{reset_link}

This link expires in 15 minutes.

If you didn’t request this, ignore this email.
        """

        mail.send(msg)

        flash("Password reset link sent to your email.", "success")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=900  # 15 minutes
        )
    except:
        flash("Reset link is invalid or expired.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first_or_404()

    if request.method == "POST":
        password = request.form.get("password")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(request.url)

        user.password = generate_password_hash(password)
        db.session.commit()

        flash("Password updated successfully. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# =========================
# USER DASHBOARD
# =========================
@app.route("/dashboard")
@login_required
def user_dashboard():
    orders = Order.query.filter_by(user_id=current_user.id) \
        .order_by(Order.created_at.desc()).all()

    return render_template(
        "dashboard_user.html",
        orders=orders
    )

# =========================
# USER: NOTIFICATIONS
@app.route("/notifications")
@login_required
def notifications():
    notifications = Notification.query.filter(
        (Notification.user_id == current_user.id) | (Notification.user_id == None)
    ).order_by(Notification.created_at.desc()).all()

    # ✅ MARK AS READ
    Notification.query.filter(
        (Notification.user_id == current_user.id) | (Notification.user_id == None),
        Notification.is_read == False
    ).update({"is_read": True})

    db.session.commit()

    return render_template("notifications.html", notifications=notifications)

@app.route("/notifications/read/<int:id>")
@login_required
def read_notification(id):
    notif = Notification.query.get_or_404(id)

    if notif.user_id not in (None, current_user.id):
        abort(403)

    notif.is_read = True
    db.session.commit()

    return redirect(url_for("notifications"))

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        count = Notification.query.filter(
            ((Notification.user_id == None) | (Notification.user_id == current_user.id)) &
            (Notification.is_read == False)
        ).count()
    else:
        count = 0

    return dict(notification_count=count)


# =========================
# USER CHAT
@app.route("/chat", methods=["GET", "POST"])
@login_required
def user_chat():
    if request.method == "POST":
        msg = ChatMessage(
            user_id=current_user.id,
            sender="user",
            message=request.form["message"]
        )
        db.session.add(msg)
        db.session.commit()

        return redirect(url_for("user_chat"))

    # 🔹 MARK ADMIN MESSAGES AS READ
    ChatMessage.query.filter_by(
        user_id=current_user.id,
        sender="admin",
        is_read=False
    ).update({"is_read": True})

    db.session.commit()

    messages = ChatMessage.query.filter_by(
        user_id=current_user.id
    ).order_by(ChatMessage.created_at.asc()).all()

    return render_template("chat.html", messages=messages)

@app.route("/chat/<int:user_id>")
@login_required
def user_chat_with_id(user_id):

    # 🔵 MARK MESSAGES AS READ
    ChatMessage.query.filter_by(
        receiver_id=current_user.id,
        sender_id=user_id,
        is_read=False
    ).update({"is_read": True})
    db.session.commit()

    messages = ChatMessage.query.filter(
        (ChatMessage.sender_id == current_user.id) &
        (ChatMessage.receiver_id == user_id) |
        (ChatMessage.sender_id == user_id) &
        (ChatMessage.receiver_id == current_user.id)
    ).order_by(ChatMessage.created_at).all()

    return render_template("chat.html", messages=messages)


# =========================
# ADMIN: CHAT WITH USER
@app.route("/admin/chat/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_chat_user(user_id):
    if current_user.role not in ["admin", "superadmin"]:
        abort(403)

    if request.method == "POST":
        msg = request.form.get("message")
        if msg:
            chat = ChatMessage(
                sender="admin",
                message=msg,
                user_id=user_id
            )
            db.session.add(chat)
            db.session.commit()

    messages = ChatMessage.query.filter_by(
        user_id=user_id
    ).order_by(ChatMessage.created_at.asc()).all()

    user = User.query.get_or_404(user_id)

    return render_template(
        "admin_chat_user.html",
        messages=messages,
        user=user
    )

@app.route("/admin/chats")
@login_required
def admin_chats():
    if current_user.role not in ["admin", "superadmin"]:
        abort(403)

    users = (
        db.session.query(User)
        .join(ChatMessage)
        .group_by(User.id)
        .all()
    )

    return render_template("admin_chats.html", users=users)

@app.route("/admin/chat/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_chat_view(user_id):
    if current_user.role not in ["admin", "superadmin"]:
        abort(403)

    if request.method == "POST":
        msg = ChatMessage(
            user_id=user_id,
            sender="admin",
            message=request.form["message"]
        )
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for("admin_chat_view", user_id=user_id))

    messages = ChatMessage.query.filter_by(
        user_id=user_id
    ).order_by(ChatMessage.created_at).all()

    ChatMessage.query.filter_by(
        user_id=user_id,
        sender="user",
        is_read=False
    ).update({"is_read": True})
    db.session.commit()

    return render_template("admin_chat_view.html", messages=messages)

# =========================
# ADMIN: VIDEOS
@app.route("/admin/videos", methods=["GET", "POST"])
@login_required
def admin_videos():
    if current_user.role not in ["admin", "superadmin"]:
        abort(403)

    if request.method == "POST":
        video = request.files.get("video")
        title = request.form.get("title")

        if not video:
            flash("Please upload a video", "danger")
            return redirect(url_for("admin_videos"))

        filename = secure_filename(video.filename)
        save_path = os.path.join(
            app.root_path, "static/uploads/videos", filename
        )
        video.save(save_path)

        new_video = Video(
            title=title,
            video_file=filename
        )
        db.session.add(new_video)
        db.session.commit()

        flash("Video uploaded successfully", "success")
        return redirect(url_for("admin_videos"))

    videos = Video.query.order_by(Video.created_at.desc()).all()
    return render_template("admin/videos.html", videos=videos)

@app.route("/admin/videos/delete/<int:video_id>", methods=["POST"])
@login_required
def delete_video(video_id):
    if current_user.role not in ["admin", "superadmin"]:
        abort(403)

    video = Video.query.get_or_404(video_id)

    file_path = os.path.join(
        app.root_path, "static/uploads/videos", video.video_file
    )

    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(video)
    db.session.commit()

    flash("Video deleted", "success")
    return redirect(url_for("admin_videos"))

# =========================
# VIDEO FEED
@app.route("/videos")
def video_feed():

    videos = Video.query.filter_by(is_active=True).all()

    video_data = []
    for v in videos:
        video_data.append({
            "video": v,
            "likes": VideoLike.query.filter_by(video_id=v.id).count(),
            "liked": (
                VideoLike.query.filter_by(
                    video_id=v.id,
                    user_id=current_user.id
                ).first() is not None
            ) if current_user.is_authenticated else False
        })

    return render_template("videos.html", videos=video_data)


# ========================= 
# VIDEO LIKE
@app.route("/video/<int:video_id>/like", methods=["POST"])
@login_required
def like_video(video_id):
    existing = VideoLike.query.filter_by(
        video_id=video_id,
        user_id=current_user.id
    ).first()

    if existing:
        db.session.delete(existing)  # unlike
        liked = False
    else:
        db.session.add(VideoLike(
            video_id=video_id,
            user_id=current_user.id
        ))
        liked = True

    db.session.commit()

    # 🔥 If AJAX request → return JSON (NO RELOAD)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        likes_count = VideoLike.query.filter_by(video_id=video_id).count()
        return jsonify({
            "success": True,
            "liked": liked,
            "likes": likes_count
        })

    # Fallback (normal form submit)
    return redirect(request.referrer)





# =========================
# ADMIN DASHBOARD
# =========================
@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    return render_template(
        "dashboard_admin.html",
        products=Product.query.all(),
        categories=Category.query.all(),
        users=User.query.all()
    )

@app.route("/admin/users")
@login_required
def admin_users():
    admin_required()

    users = User.query.order_by(User.id.desc()).all()
    return render_template("add_users.html", users=users)
def admin_required():
    if current_user.role not in ["admin", "superadmin"]:
        abort(403)

@app.route("/admin/users/add", methods=["GET", "POST"])
@login_required
def admin_add_user():
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form["name"]
        whatsapp = request.form["whatsapp"].strip()
        email = request.form.get("email")
        password = request.form["password"]
        role = request.form.get("role", "user")

        # ✅ Prevent duplicate WhatsApp
        existing = User.query.filter_by(whatsapp=whatsapp).first()
        if existing:
            flash("WhatsApp number already exists", "danger")
            return redirect(url_for("admin_add_user"))

        user = User(
            name=name,
            whatsapp=whatsapp,
            email=email,
            address="",
            role=role
        )

        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        if role == "admin" and current_user.role != "superadmin":
            flash("You are not allowed to create admins", "danger")


        flash("User added successfully", "success")
        return redirect(url_for("admin_users"))

    return render_template("add_users.html")

@app.route("/admin/users/<int:user_id>/toggle-admin")
@login_required
def toggle_admin(user_id):
    admin_required()

    user = User.query.get_or_404(user_id)

    if user.role == "user":
        user.role = "admin"
    elif user.role == "admin":
        user.role = "user"

    db.session.commit()
    flash("User role updated", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/delete")
@login_required
def delete_user(user_id):
    admin_required()

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot delete yourself", "danger")
        return redirect(url_for("add_users"))

    db.session.delete(user)
    db.session.commit()

    flash("User deleted", "success")
    return redirect(url_for("admin_users"))
# =========================
# ADMIN: NOTIFICATIONS
@app.route("/admin/notifications", methods=["GET", "POST"])
@login_required
def admin_notifications():

    # 🔒 Only admins
    if current_user.role not in ["admin", "superadmin"]:
        abort(403)

    if request.method == "POST":
        title = request.form["title"]
        message = request.form["message"]
        user_id = request.form.get("user_id")

        notif = Notification(
            title=title,
            message=message,
            user_id=None if user_id == "all" else int(user_id)
        )

        db.session.add(notif)
        db.session.commit()

        flash("Notification sent successfully", "success")
        return redirect(url_for("admin_notifications"))

    users = User.query.order_by(User.name).all()

    return render_template(
        "admin_notifications.html",
        users=users
    )

# =========================
# ADMIN: CATEGORIES
# =========================
@app.route("/admin/category/add", methods=["GET", "POST"])
@login_required
def add_category():
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    if request.method == "POST":
        name_en = request.form.get("name_en")
        name_fr = request.form.get("name_fr")
        icon = request.form.get("icon")  # ✅ ICON, NOT IMAGE

        # Safety check
        if not name_en or not name_fr or not icon:
            flash("All fields are required", "danger")
            return redirect(url_for("add_category"))

        category = Category(
            name_en=name_en,
            name_fr=name_fr,
            icon=icon
        )

        db.session.add(category)
        db.session.commit()

        flash("Category added successfully", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_category.html")

# =========================
# ADMIN: EDIT CATEGORY
# =========================
@app.route("/admin/category/<int:category_id>/edit", methods=["GET", "POST"])
@login_required
def edit_category(category_id):
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    category = Category.query.get_or_404(category_id)

    if request.method == "POST":
        category.name_en = request.form["name_en"]
        category.name_fr = request.form["name_fr"]
        category.icon = request.form["icon"]

        db.session.commit()
        flash("Category updated successfully", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("edit_category.html", category=category)


# =========================
# ADMIN: DELETE CATEGORY
# =========================
@app.route("/admin/category/<int:category_id>/delete", methods=["POST"])
@login_required
def delete_category(category_id):
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()

    flash("Category deleted", "warning")
    return redirect(url_for("admin_dashboard"))

# =========================
# ADMIN: PRODUCTS
# =========================
@app.route("/admin/product/add", methods=["GET", "POST"])
@login_required
def add_product():
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    categories = Category.query.all()

    if request.method == "POST":
        product = Product(
            name_en=request.form["name_en"],
            name_fr=request.form["name_fr"],
            description_en=request.form["description_en"],
            description_fr=request.form["description_fr"],
            shop_name=request.form["shop_name"],
            shop_location=request.form["shop_location"],
            price=float(request.form["price"]),
            currency=request.form.get("currency", "USD"),  # ✅ DEFAULT USD
            category_id=int(request.form["category_id"]),
            is_new=bool(request.form.get("is_new")),
            is_trending=bool(request.form.get("is_trending")),
            is_featured=bool(request.form.get("is_featured")),
            is_on_sale=bool(request.form.get("is_on_sale")),
        )

        db.session.add(product)
        db.session.commit()  # ✅ get product.id first

        # =========================
        # SAVE PRODUCT IMAGES
        # =========================
        for file in request.files.getlist("images"):
            if file and allowed_file(file.filename):
                original_name = secure_filename(file.filename)

                # 🔒 avoid filename collision
                unique_name = f"{product.id}_{original_name}"

                file.save(os.path.join(PRODUCT_UPLOAD_FOLDER, unique_name))

                db.session.add(ProductImage(
                    product_id=product.id,
                    image=f"products/{unique_name}"
                ))

        db.session.commit()

        flash("Product added successfully", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_product.html", categories=categories)

# =========================
# SET CURRENCY
# =========================
@app.route("/set-currency/<currency>")
def set_currency(currency):
    if currency in CURRENCIES:
        session["currency"] = currency
    return redirect(request.referrer or url_for("home"))

@app.before_request
def load_currency():
    g.currency = session.get("currency", "USD")  # ✅ DEFAULT USD


@app.template_filter("money")
def money(product):
    amount = product.price
    currency = product.currency

    rates = {
        "USD": 1,
        "KES": 130,
        "CDF": 2500,
        "EUR": 0.93,
        "TZS": 2700,
        "UGX": 3700
    }

    selected = getattr(g, "currency", "USD")
    usd_price = amount / rates[currency]
    converted = usd_price * rates[selected]

    symbols = {
        "USD": "$",
        "KES": "KES ",
        "CDF": "CDF ",
        "EUR": "€",
        "TZS": "TZS ",
        "UGX": "UGX "
    }

    return f"{symbols[selected]}{converted:,.2f}"

@app.template_filter("amount")
def amount(value):
    if value is None:
        return ""

    selected = getattr(g, "currency", "USD")

    rates = {
        "USD": 1,
        "KES": 130,
        "CDF": 2500,
        "EUR": 0.93,
        "TZS": 2700,
        "UGX": 3700
    }

    symbols = {
        "USD": "$",
        "KES": "KES ",
        "CDF": "CDF ",
        "EUR": "€",
        "TZS": "TZS ",
        "UGX": "UGX "
    }

    converted = value * rates[selected]  # ✅ MULTIPLY

    return f"{symbols[selected]}{converted:,.0f}"

# =========================
# UPLOAD FOLDERS
# =========================
BASE_UPLOAD_FOLDER = os.path.join("static", "uploads")

PRODUCT_UPLOAD_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "products")
CATEGORY_UPLOAD_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "categories")

os.makedirs(PRODUCT_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CATEGORY_UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}


@app.route("/admin/product/edit/<int:product_id>", methods=["GET", "POST"])
@login_required
def edit_product(product_id):
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    product = Product.query.get_or_404(product_id)
    categories = Category.query.all()

    if request.method == "POST":
        product.name_en = request.form["name_en"]
        product.name_fr = request.form["name_fr"]
        product.description_en = request.form["description_en"]
        product.description_fr = request.form["description_fr"]
        product.price = float(request.form["price"])
        currency = request.form.get("currency", "USD")
        product.category_id = int(request.form["category_id"])

        product.is_new = bool(request.form.get("is_new"))
        product.is_trending = bool(request.form.get("is_trending"))
        product.is_featured = bool(request.form.get("is_featured"))
        product.is_on_sale = bool(request.form.get("is_on_sale"))

        db.session.commit()
        flash("Product updated", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template(
        "edit_product.html",
        product=product,
        categories=categories
    )


@app.route("/admin/product/delete/<int:product_id>")
@login_required
def delete_product(product_id):
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    product = Product.query.get_or_404(product_id)

    for img in product.images:
        path = os.path.join(UPLOAD_FOLDER, img.image)
        if os.path.exists(path):
            os.remove(path)
        db.session.delete(img)

    db.session.delete(product)
    db.session.commit()

    flash("Product deleted", "success")
    return redirect(url_for("admin_dashboard"))


# =========================
# ADMIN: BANNERS
@app.route("/admin/banners", methods=["GET", "POST"])
@login_required
def admin_banners():
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    if request.method == "POST":
        image = request.files["image"]

        filename = secure_filename(image.filename)
        image.save(os.path.join("static/uploads/banners", filename))

        banner = Banner(
            image=f"banners/{filename}",
            title=request.form["title"],
            description=request.form.get("description"),
            price=request.form.get("price"),
            currency=request.form.get("currency", "USD"),
            contact=request.form.get("contact")
        )

        db.session.add(banner)
        db.session.commit()
        flash("Banner added", "success")

    banners = Banner.query.order_by(Banner.created_at.desc()).all()
    return render_template("admin_banners.html", banners=banners)

@app.route("/admin/banners/add", methods=["GET", "POST"])
@login_required
def admin_add_banner():
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    if request.method == "POST":
        image = request.files["image"]  # main image
        extra_images = request.files.getlist("images")  # new
        title = request.form["title"]
        description = request.form["description"]
        contact = request.form.get("contact")
        tel = request.form.get("tel")

        is_active = bool(request.form.get("is_active"))

        upload_folder = os.path.join("static", "uploads", "banners")
        os.makedirs(upload_folder, exist_ok=True)

        main_filename = secure_filename(image.filename)
        image.save(os.path.join(upload_folder, main_filename))

        cta_text = request.form.get("cta_text") or "CONTACT US"
        banner = Banner(
            image=f"banners/{main_filename}",
            title=title,
            description=description,
            contact=contact,
            cta_text=cta_text,
            cta_color = request.form.get("cta_color") or "#ff3b3b",
            tel=tel,
            is_active=is_active
        )

        db.session.add(banner)
        db.session.commit()

        for img in extra_images:
            if img and img.filename:
                filename = secure_filename(img.filename)
                img.save(os.path.join(upload_folder, filename))
                db.session.add(BannerImage(
                    banner_id=banner.id,
                    image=f"banners/{filename}"
                ))

        db.session.commit()

        flash("Banner added successfully", "success")
        return redirect(url_for("admin_banners"))

    return render_template("admin_add_banner.html")

@app.route("/admin/banners/<int:banner_id>/delete")
@login_required
def delete_banner(banner_id):
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    banner = Banner.query.get_or_404(banner_id)
    db.session.delete(banner)
    db.session.commit()

    flash("Banner deleted", "success")
    return redirect(url_for("admin_banners"))


# =========================
# ADMIN: ORDERS
# =========================
@app.route("/admin/orders")
@login_required
def admin_orders():
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin_orders.html", orders=orders)
# =========================
# ADMIN: ORDER DETAIL
# =========================
@app.route("/admin/order/<int:order_id>", methods=["GET", "POST"])
@login_required
def admin_order_detail(order_id):
    if current_user.role not in ["admin", "superadmin"]:
        return redirect(url_for("home"))

    order = Order.query.get_or_404(order_id)

    if request.method == "POST":
        order.payment_status = request.form.get("payment_status")
        order.delivery_status = request.form.get("delivery_status")
        db.session.commit()
        flash("Order updated successfully", "success")
        return redirect(url_for("admin_orders"))

    return render_template(
        "admin_order_detail.html",
        order=order
    )
# =========================
# ADMIN: UPDATE ORDER STATUS
# =========================
@app.route("/admin/order/<int:order_id>/update", methods=["POST"])
@login_required
def update_order_status(order_id):
    if current_user.role not in ["admin", "superadmin"]:
        flash("Access denied", "danger")
        return redirect(url_for("home"))

    order = Order.query.get_or_404(order_id)

    order.payment_status = request.form.get("payment_status")
    order.delivery_status = request.form.get("delivery_status")

    db.session.commit()

    flash("Order status updated successfully", "success")
    return redirect(url_for("admin_order_detail", order_id=order.id))

@app.route("/set-language/<lang>")
def set_language(lang):
    if lang in ["en", "fr"]:
        session["lang"] = lang
    return redirect(request.referrer or url_for("home"))

@app.context_processor
def inject_translations():
    translations = {
        "en": {
            "add_to_cart": "Add to Cart",
            "shop_by_category": "Shop by Category",
            "new_arrivals": "New Arrivals",
            "trending": "Trending",
            "on_sale": "On Sale",
            "for_you": "For You",
            "price": "Price",
            "logout": "Logout",
            "login": "Login",
            "home": "Home",
            "cart": "Cart",
            "all_rights_reserved.": "All rights reserved.",
            "proceed_to_checkout": "Proceed to Checkout",
            "your_cart_is_empty": "Your cart is empty.",
            "new": "NEW",
            "trending": "TRENDING",
            "on_sale": "ON SALE",
            "featured": "FEATURED",
            "payment_information": "Payment Information",
            "order_number": "Order Number",
            "total_amount": "Total Amount",
            "copy": "Copy",
            "account_number": "Account Number",
            "amount": "Amount",
            "contact_information": "Contact Information",
            "delivery_address": "Delivery Address",
            "i_have_completed_payment": "I Have Completed Payment",
            "my_orders": "My Orders",
            "you_have_not_placed_any_orders_yet": "You have not placed any orders yet.",
            "login | guzones": "Login | Guzones",
            "signup | guzones": "Signup | Guzones",
            "login_to_guzones": "Login to Guzones",
            "signup_to_guzones": "Signup to Guzones",
            "dont_have_an_account": "Don't have an account?",
            "create_one_here.": "Create one here.",
            "customers_also_viewed": "Customers Also Viewed",
            "no_products_found.": "No products found.",
            "search_results_for": "Search results for",
            "create_an_account": "Create an Account",
            "full_name": "Full Name",
            "your_full_name": "Your full name",
            "email_(optional)": "Email (optional)",
            "your_address": "Your address",
            "your_delivery_address": "Your delivery address",
            "password": "Password",
            "sign_up": "Sign Up",
            "already_have_an_account?": "Already have an account?",
            "log_in_here.": "Log in here.",
            "my_account": "My Account",
            "cart": "Cart"
        },
        "fr": {
            "add_to_cart": "Ajouter...",
            "shop_by_category": "Acheter par catégorie",
            "new_arrivals": "Nouveautés",
            "trending": "Tendances",
            "on_sale": "Promotions",
            "for_you": "Pour vous",
            "price": "Prix",
            "logout": "Déconnexion",
            "login": "Connexion",
            "home": "Accueil",
            "cart": "Panier",
            "all_rights_reserved.": "Tous droits réservés.",
            "proceed_to_checkout": "Payer maintenant",
            "your_cart_is_empty": "Votre panier est vide.",
            "new": "NOUVEAU",
            "trending": "TENDANCES",
            "on_sale": "PROMOTION",
            "featured": "EN VEDETTE",
            "payment_information": "Informations de paiement",
            "order_number": "Numéro de commande",
            "total_amount": "Montant total",
            "copy": "Copier",
            "account_number": "Numéro de compte",
            "amount": "Montant",
            "contact_information": "Informations de contact",
            "delivery_address": "Adresse de livraison",
            "i_have_completed_payment": "J'ai effectué le paiement",
            "my_orders": "Mes commandes",
            "you_have_not_placed_any_orders_yet": "Vous n'avez pas encore passé de commandes.",
            "login | guzones": "Connexion | Guzones",
            "signup | guzones": "Inscription | Guzones",
            "login_to_guzones": "Connectez-vous à Guzones",
            "signup_to_guzones": "Inscrivez-vous à Guzones",
            "dont_have_an_account": "Vous n'avez pas de compte ?",
            "create_one_here.": "Créez-en un ici.",
            "customers_also_viewed": "Les clients ont également vu",
            "no_products_found.": "Aucun produit trouvé.",
            "search_results_for": "Résultats de recherche pour",
            "create_an_account": "Créer un compte",
            "full_name": "Nom complet",
            "your_full_name": "Votre nom complet",
            "email_(optional)": "Email (optionnel)",
            "your_address": "Votre adresse",
            "your_delivery_address": "Votre adresse de livraison",
            "password": "Mot de passe",
            "sign_up": "S'inscrire",
            "already_have_an_account?": "Vous avez déjà un compte?",
            "log_in_here.": "Connectez-vous ici.",
            "my_account": "Mon compte",
            "cart": "Panier"
        }
    }

    return dict(t=translations.get(g.lang, translations["en"]))

# =========================



# =========================
# START
# =========================
if __name__ == "__main__":
    app.run(debug=True)