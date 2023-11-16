from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Length, EqualTo
from flask_ckeditor import CKEditorField


# ============================== START OF FORMS ==============================
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    # Todo: Add authors option
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(),
                                                     Length(min=8, max=16),
                                                     EqualTo('password_confirm',
                                                             message='Passwords must match')])
    password_confirm = PasswordField("Repeat Password", validators=[DataRequired(), Length(min=8, max=16)])
    email = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class CommentForm(FlaskForm):
    comment_body = CKEditorField("Leave a comment below:", validators=[DataRequired()])
    submit = SubmitField("Post Comment")
# ============================== END OF FORMS ==============================