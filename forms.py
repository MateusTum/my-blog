from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
from flask_wtf import FlaskForm
from flask_ckeditor import CKEditorField


# Form for new post
class NewPostForm(FlaskForm):
    author = StringField('Your Name', validators=[DataRequired()])
    title = StringField('Blog Post Title', validators=[DataRequired()])
    subtitle = StringField('Subtitle', validators=[DataRequired()])
    img_url = StringField('Blog Image URL', validators=[DataRequired(), URL()])
    body = CKEditorField('Blog Content', validators=[DataRequired()])
    publish_post = SubmitField('Submit Post')