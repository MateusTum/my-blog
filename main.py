from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_ckeditor import CKEditor
from datetime import date
from forms import NewPostForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
Bootstrap5(app)

# CKEditor
ckeditor = CKEditor()
ckeditor.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLE
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

# First run:
# with app.app_context():
#     db.create_all()


@app.route('/')
def get_all_posts():
    query_all_posts = db.session.execute(db.select(BlogPost).order_by(desc(BlogPost.id))).scalars()
    posts = [post for post in query_all_posts]
    return render_template("index.html", all_posts=posts)


@app.route('/post/<int:post_id>', methods=["GET"])
def show_post(post_id):
    requested_post = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
    return render_template("post.html", post=requested_post)


@app.route('/add-new-post', methods=["GET", "POST"])
def add_new_post():
    form = NewPostForm()
    if request.method == 'POST' and form.validate_on_submit():
        post = BlogPost(
            title=request.form.get('title'),
            subtitle=request.form.get('subtitle'),
            author=request.form.get('author'),
            img_url=request.form.get('img_url'),
            body=request.form.get('body'),
            date=date.today().strftime('%B %d, %Y')
        )
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    else:
        h1 = "New Post"
        return render_template("make-post.html", form=form, h1=h1)


@app.route('/edit-post/<post_id>', methods=["GET", "POST"])
def edit_post(post_id):
    form = NewPostForm()
    post = db.get_or_404(BlogPost, post_id)
    if request.method == 'GET':
        h1 = "Edit Post"
        form.title.data = post.title
        form.subtitle.data = post.subtitle
        form.author.data = post.author
        form.img_url.data = post.img_url
        form.body.data = post.body
        return render_template("make-post.html", form=form, h1=h1)
    elif request.method == 'POST' and form.validate_on_submit():
        post.title = request.form.get('title')
        post.subtitle = request.form.get('subtitle')
        post.author = request.form.get('author')
        post.img_url = request.form.get('img_url')
        post.body = request.form.get('body')
        db.session.commit()
        return redirect(url_for('show_post', post_id=post.id))


@app.route('/delete-post/<post_id>', methods=["GET"])
def delete_post(post_id):
    if request.method == 'GET':
        post = db.get_or_404(BlogPost, post_id)
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5003)
