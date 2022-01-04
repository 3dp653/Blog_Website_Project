import os
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, flash, abort
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as sql
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, UserLoginForm, NewUserForm, CommentForm
from flask_gravatar import Gravatar

load_dotenv(".env")
print(os.environ.get("SECRET_KEY"))


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

# Initialize Gravatar
gravatar = Gravatar(app)

# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# #CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = sql.Column(sql.Integer, primary_key=True)
    author_id = sql.Column(sql.Integer, sql.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = sql.Column(sql.String(250), unique=True, nullable=False)
    subtitle = sql.Column(sql.String(250), nullable=False)
    date = sql.Column(sql.String(250), nullable=False)
    body = sql.Column(sql.Text, nullable=False)
    img_url = sql.Column(sql.String(250), nullable=False)
    comments = relationship("Comments", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = sql.Column(sql.Integer, primary_key=True)
    email = sql.Column(sql.String(1000), unique=True, nullable=False)
    password = sql.Column(sql.String(1000), nullable=False)
    name = sql.Column(sql.String(1000), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="author")


class Comments(db.Model):
    __tablename__ = "comments"
    id = sql.Column(sql.Integer, primary_key=True)
    text = sql.Column(sql.String(1000), nullable=False)
    author_id = sql.Column(sql.Integer, sql.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    post_id = sql.Column(sql.Integer, sql.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()


# Decorator
def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() == "1":
            return function(*args, **kwargs)
        else:
            return abort(403)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, user=User)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = NewUserForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flash("That email is already in use, consider logging in?")
            return redirect(url_for('register'))
        else:
            password_hash = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=email,
                password=password_hash,
                name=form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = UserLoginForm()

    if login_form.validate_on_submit():
        login_email = login_form.email.data
        user = User.query.filter_by(email=login_email).first()

        if user:
            if check_password_hash(
                pwhash="pbkdf2:sha256:150000$RHovO3cx$9ea56e6d0e7ad27513bc2fba9a5985cdccdb9fbef9a7fac72e1bfc5d5b6e3046",
                password=login_form.password.data
            ):
                login_user(user)
                return redirect(url_for('get_all_posts'))

            else:
                flash("Invalid password!")
                return redirect(url_for('login'))

        else:
            flash("That email doesn't exist! Try registering?")
            return redirect(url_for('login'))

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():

        if current_user.is_authenticated:
            new_comment = Comments(
                text=comment_form.comment.data,
                author_id=current_user.get_id(),
                post_id=post_id,
                # gravatar=gravatar,
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("You need to be logged in to submit a comment!")
            return redirect(url_for('login'))

    return render_template(
        "post.html",
        post=requested_post,
        user=User,
        form=comment_form
    )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
