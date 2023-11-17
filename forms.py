from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, DateField
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
    username = StringField("Username", validators=[DataRequired(), Length(min=4, max=10)])
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


class ProfileForm(FlaskForm):
    username = StringField("Username")
    first_name = StringField("First Name")
    last_name = StringField("Last Name")
    # TODO: ADD THESE THINGS BELOW TO THE USER TABLE IN SQALCHEMY, all of them are nullable
    date_of_birth = DateField("Date of Birth")
    # profile_picture =
    city = StringField("City")
    country = StringField("Country")
    # TODO: ADD AN OPTION TO CHECK FOR PASSWORD
    submit = SubmitField("Edit Profile")
# ============================== END OF FORMS ==============================