from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ProfileForm
from gravatar import *
import os

# ============================== GENERAL CONFIGS ==============================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')

# Bootstrap5
Bootstrap5(app)

# CKEditor
ckeditor = CKEditor()
ckeditor.init_app(app)

# FLASK LOGIN CONFIGS
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy()
db.init_app(app)
# ============================== END OF GENERAL CONFIGS ==============================


# ==============================  TABLES ==============================
# ASSOCIATION TABLES
user_post_association = db.Table('user_post_association', db.Model.metadata,
                                 db.Column('user_id', db.Integer, db.ForeignKey('blog_users.id')),
                                 db.Column('post_id', db.Integer, db.ForeignKey('blog_posts.id'))
                                 )

user_comment_association = db.Table('user_comment_association', db.Model.metadata,
                                    db.Column('user_id', db.Integer, db.ForeignKey('blog_users.id')),
                                    db.Column('comment_id', db.Integer, db.ForeignKey('blog_comments.id'))
                                    )

user_user_association = db.Table('user_user_association', db.Model.metadata,
                                 db.Column('follower_id', db.Integer, db.ForeignKey('blog_users.id')),
                                 db.Column('followed_id', db.Integer, db.ForeignKey('blog_users.id'))
                                 )


# DATABASE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "blog_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False)
    # Personal info below
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    date_of_birth = db.Column(db.DateTime, nullable=True)
    city = db.Column(db.String, nullable=True)
    country = db.Column(db.String, nullable=True)
    gravatar_url = db.Column(db.String)
    # End of personal info
    posts = db.Relationship("BlogPost", secondary=user_post_association, back_populates="authors")
    comments = db.Relationship("Comment", back_populates="author")
    followed = db.Relationship("User", secondary=user_user_association,
                               primaryjoin=(user_user_association.c.follower_id == id),
                               secondaryjoin=(user_user_association.c.followed_id == id),
                               back_populates="followers")
    followers = db.Relationship("User", secondary=user_user_association,
                                primaryjoin=(user_user_association.c.followed_id == id),
                                secondaryjoin=(user_user_association.c.follower_id == id),
                                back_populates="followed")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    authors = db.Relationship("User", secondary=user_post_association, back_populates="posts")
    comments = db.Relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "blog_comments"
    id = db.Column(db.Integer, primary_key=True)
    comment_body = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("blog_users.id"))
    author = db.Relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = db.Relationship("BlogPost", back_populates="comments")


# ============================== END OF TABLES ==============================
# ============================== WRAPPER FUNCTION FOR ADMINS ==============================
def admin_only(func):
    @wraps(func)
    def check_admin(*args, **kwargs):
        if not current_user.role == "admin":
            abort(403)
        return func(*args, **kwargs)

    return check_admin


def user_locked(func):
    @wraps(func)
    def check_user(*args, **kwargs):
        return func(*args, **kwargs, username=current_user.username)

    return check_user


# ============================== END OF WRAPPER FUNCTION ==============================
with app.app_context():
    db.create_all()


# ============================== START OF APP ROUTES ==============================
@login_manager.user_loader
def load_user(user_id):
    return db.session().get(User, int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    def check_if_email_already_exists():
        email_to_register = request.form.get('email')
        email_query = User.query.filter(User.email == email_to_register)
        email_query_result = email_query.scalar()
        return email_query_result

    def check_if_username_already_exists():
        username_to_register = request.form.get('username')
        username_query = User.query.filter(User.username == username_to_register)
        username_query_result = username_query.scalar()
        return username_query_result

    def get_hashed_password():
        crude_password = request.form.get('password')
        hashed_password = generate_password_hash(crude_password, method='pbkdf2:sha256', salt_length=8)
        return hashed_password

    register_form = RegisterForm()

    if request.method == 'POST' and register_form.validate_on_submit:
        if check_if_email_already_exists():
            flash('Email already in use')
            return redirect(url_for('login'))
        if check_if_username_already_exists():
            flash('Username already in use')
            return redirect(url_for('login'))
        else:
            new_user = User(
                first_name=request.form.get('first_name').title(),  # type: ignore
                last_name=request.form.get('last_name').title(),  # type: ignore
                username=request.form.get('username'),  # type: ignore
                email=request.form.get('email'),  # type: ignore
                password=get_hashed_password(),  # type: ignore
                role="user",  # type: ignore
                gravatar_url=get_gravatar_url(email=request.form.get('email'))  # type: ignore
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit:
        typed_email = request.form.get('email')
        typed_password = request.form.get('password')
        user = db.session.query(User).filter(User.email == typed_email).scalar()
        if not user:
            flash('Email doesnt exist in database')
            return redirect(url_for('login'))
        elif check_password_hash(pwhash=user.password, password=typed_password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    post_comments = requested_post.comments
    comment_form = CommentForm()
    comments_field = False if not current_user.is_authenticated else True
    if current_user.is_authenticated:
        if request.method == 'POST' and comment_form.validate_on_submit:
            new_comment = Comment(
                comment_body=request.form.get('comment_body'),
                date=date.today().strftime("%B %d, %Y"),
            )
            db.session.add(new_comment)
            current_user.comments.append(new_comment)
            requested_post.comments.append(new_comment)
            db.session.commit()
            return redirect(url_for('get_all_posts'))

    return render_template("post.html",
                           post=requested_post,
                           form=comment_form,
                           comments=comments_field,
                           post_comments=post_comments
                           )


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    create_post_form = CreatePostForm()
    if create_post_form.validate_on_submit():
        new_post = BlogPost(
            title=create_post_form.title.data,
            subtitle=create_post_form.subtitle.data,
            body=create_post_form.body.data,
            img_url=create_post_form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        current_user.posts.append(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=create_post_form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        authors=post.authors,
        body=post.body
    )
    if request.method == 'POST' and edit_form.validate_on_submit():
        post.title = request.form.get('title')
        post.subtitle = request.form.get('subtitle')
        post.img_url = request.form.get('img_url')
        post.body = request.form.get('body')
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete-post/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete-comment")
@login_required
@admin_only
def delete_comment():
    post_id = request.args.get('post_id')
    comment_id = request.args.get('comment_id')
    current_post = db.get_or_404(BlogPost, post_id)
    comment_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=current_post.id))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/user/<username>", methods=['GET'])
@login_required
def get_user_profile(username):
    user_query = User.query.filter(User.username == username)
    user = user_query.scalar()
    show_edit_options = True if current_user == user else False
    return render_template("user-profile.html",
                           user=user,
                           edit=show_edit_options,
                           followers_number=len(user.followers),
                           followed_number=len(user.followed)
                           )


@app.route("/edit-profile", methods=['GET', 'POST'])
@login_required
@user_locked
def edit_user_profile(username):
    user_query = User.query.filter(User.username == username)
    user = user_query.scalar()
    form = ProfileForm(
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
        date_of_birth=user.date_of_birth,
        # profile_picture=
        city=user.city,
        country=user.country
    )
    if request.method == 'POST' and form.validate_on_submit:
        user.username = form.username.data
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.date_of_birth = form.date_of_birth.data
        # user.profile_picture = form.profile_picture.data
        user.city = form.city.data
        user.country = form.country.data
        db.session.commit()
        return redirect(url_for("get_user_profile", username=user.username))

    return render_template("edit-profile.html", user=user, form=form)


# ============================== END OF APP ROUTES ==============================

if __name__ == "__main__":
    app.run(debug=False)
