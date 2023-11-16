from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from gravatar import *

# ============================== GENERAL CONFIGS ==============================
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

# Bootstrap5
Bootstrap5(app)

# CKEditor
ckeditor = CKEditor()
ckeditor.init_app(app)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)
# ============================== END OF GENERAL CONFIGS ==============================


# ==============================  TABLES ==============================
# ASSOCIATION TABLES
user_post_association = db.Table('user_post_association', db.Model.metadata,
                                 db.Column('user_id', db.Integer, db.ForeignKey('blog_users.id')),
                                 db.Column('post_id', db.Integer, db.ForeignKey('blog_posts.id')),
                                 )

user_comment_association = db.Table('user_comment_association', db.Model.metadata,
                                    db.Column('user_id', db.Integer, db.ForeignKey('blog_users.id')),
                                    db.Column('comment_id', db.Integer, db.ForeignKey('blog_comments.id'))
                                    )


# DATABASE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "blog_users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False)
    gravatar_url = db.Column(db.String)
    posts = db.Relationship("BlogPost", secondary=user_post_association, back_populates="authors")
    comments = db.Relationship("Comment", back_populates="author")


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
# ============================== END OF WRAPPER FUNCTION ==============================


with app.app_context():
    db.create_all()


# ============================== START OF APP ROUTES ==============================
@login_manager.user_loader
def load_user(user_id):
    # Todo: change the query methods to Session.get
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit:
        email_to_register = request.form.get('email')
        query = User.query.filter(User.email == email_to_register)
        result = query.scalar()
        if result:
            flash('Email already in use')
            return redirect(url_for('login'))
        else:
            crude_password = request.form.get('password')
            hashed_password = generate_password_hash(crude_password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                first_name=request.form.get('first_name').title(),  # type: ignore
                last_name=request.form.get('last_name').title(),  # type: ignore
                email=request.form.get('email'),  # type: ignore
                password=hashed_password,  # type: ignore
                role="admin"  # type: ignore
            )
            db.session.add(new_user)
            new_user.gravatar_url = get_gravatar_url(email=new_user.email)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


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


# ============================== END OF APP ROUTES ==============================

if __name__ == "__main__":
    app.run(debug=True, port=5002)
