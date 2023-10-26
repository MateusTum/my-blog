from flask import Flask, render_template
import requests

app = Flask(__name__)

response = requests.get("https://api.npoint.io/842fe76f5cdce43bff81")
posts = response.json()


@app.route("/")
def home():
    content = posts
    return render_template("index.html", content=content)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/post/<int:post_id>")
def get_post(post_id):
    for post in posts:
        if post["id"] == post_id:
            show_post = posts[post_id - 1]
    return render_template("post.html", post=show_post)


if __name__ == "__main__":
    app.run(debug=True)
