# In app/routes.py
import os
import random
import string
import boto3
from botocore.exceptions import ClientError
from .forms import BlogForm
from . import limiter
from datetime import datetime
from flask import (
    render_template, request, redirect, url_for,
    flash, session, current_app as app # Use current_app to access config
)
from flask_login import login_user, logout_user, login_required, current_user # Added logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Import models and db instance
from .models import db, BlogPost, AboutSection, VisitorLog, SiteSetting, Admin # Added Admin
from flask_wtf.csrf import generate_csrf

# Define allowed image types (adjust as needed)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- S3 Helper Functions ---

# Credentials might be automatically picked up if using IAM role on EC2
# Otherwise, Boto3 will look for environment variables OR the hardcoded config

# --- S3 Helper Functions ---
def get_s3_client():
    # Credentials might be automatically picked up if using IAM role on EC2
    # Otherwise, Boto3 will look for environment variables OR the hardcoded config
    s3_client = boto3.client(
        "s3",
        region_name=app.config.get('S3_REGION'),
        aws_access_key_id=app.config.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=app.config.get('AWS_SECRET_ACCESS_KEY')
    )
    return s3_client

def upload_file_to_s3(file, bucket_name, object_name=None, acl="public-read"):
    """Upload a file-like object to an S3 bucket with a random 5-char name."""

    # --- START MODIFICATION ---
    if object_name is None:
        # Generate random 5-character alphanumeric string
        random_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
        # Get the original file extension (e.g., '.jpg', '.png')
        try:
            # Use os.path.splitext to safely get the extension
            filename, extension = os.path.splitext(file.filename)
            # Ensure there is an extension and it's reasonable
            if not extension or len(extension) > 10:
                 extension = '.bin' # Default extension if unclear/invalid
        except Exception:
            extension = '.bin' # Fallback extension on error

        # Combine random name and original extension (lowercase)
        object_name = f"{random_chars}{extension.lower()}"
    # --- END MODIFICATION ---

    s3_client = get_s3_client()
    try:
        s3_client.upload_fileobj(
            file,
            bucket_name,
            object_name, # Use the generated random name
            ExtraArgs={
                "ACL": acl,
                "ContentType": file.content_type
            }
        )
        # Return the object key (the new random filename in S3)
        return object_name

    except ClientError as e:
        app.logger.error(f"S3 Upload Error: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Error uploading file '{object_name}': {e}")
        return None

# delete_file_from_s3 function remains the same
def delete_file_from_s3(bucket_name, object_name):
    """Delete a file from an S3 bucket"""
    if not object_name: # Avoid trying to delete empty keys
        app.logger.warning("Attempted to delete S3 object with empty name.")
        return False

    s3_client = get_s3_client()
    try:
        # THE ACTUAL DELETE CALL:
        s3_client.delete_object(Bucket=bucket_name, Key=object_name)
        # Log success
        app.logger.info(f"Successfully deleted {object_name} from bucket {bucket_name}")
        return True # Return True on success

    except ClientError as e:
        # Log specific AWS errors
        app.logger.error(f"S3 Delete ClientError for {object_name}: {e}")
        return False # Return False on failure
    except Exception as e:
        # Log any other unexpected errors
        app.logger.error(f"Generic error deleting file {object_name}: {e}")
        return False # Return False on failure
# --- End S3 Helper Functions ---

# --- Add Logging Helper ---
def log_visit(page_title=None, post_id=None, post_title=None):
    """Logs a visit attempt."""
    try:
        ip_address = request.remote_addr
        user_agent_string = request.headers.get('User-Agent')
        referrer_url = request.headers.get('Referer')
        requested_url = request.path # Log the path requested

        # Determine title: Use specific page title, post title, or requested path
        log_title = page_title or post_title or requested_url

        log_entry = VisitorLog(
            ip_address=ip_address,
            visit_time=datetime.utcnow(),
            blog_post_id=post_id, # Will be None for non-post pages
            blog_post_title=log_title[:150], # Use generic title, truncate
            user_agent=user_agent_string[:255] if user_agent_string else None,
            referrer=referrer_url[:255] if referrer_url else None
        )
        db.session.add(log_entry)
        db.session.commit()
        app.logger.debug(f"Logged visit: IP={ip_address}, Page={log_title}, PostID={post_id}")

    except Exception as e:
        db.session.rollback()
        # Log error but don't interrupt user request
        app.logger.error(f"Error logging visitor: {e} for path {request.path}")
# --- End Logging Helper ---


# --- Frontend Routes ---
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"]) # Keep rate limiting if desired
def index():
    # Renamed variable for clarity
    # --- START: Log visit ---
    log_visit(page_title="Homepage")
    # --- END: Log visit ---
    category_filter = request.args.get('category', 'all')
    page = request.args.get('page', 1, type=int)
    view_mode = request.args.get('view', 'grid')

    # --- Section‑level lock for Private ---
    if category_filter == 'private' and not session.get('private_section_access'):
        if request.method == 'POST':
            # Make sure csrf token is validated if using WTForms or manual token
            stored_pw_hash = SiteSetting.get("private_section_password")
            entered_pw = request.form.get('section_password')
            if stored_pw_hash and entered_pw and check_password_hash(stored_pw_hash, entered_pw):
                session['private_section_access'] = True
                flash('Private section unlocked.', 'success')
                return redirect(url_for('index', category='private', view=view_mode))
            else:
                flash('Incorrect password for Private section.', 'error')
        return render_template('section_password_prompt.html', csrf_token=generate_csrf())

    # --- Query Modification ---
    query = BlogPost.query.order_by(BlogPost.date_posted.desc())

    if category_filter == 'private':
        query = query.filter_by(category=category_filter)
        if not session.get('private_section_access'):
             query = query.filter(db.false()) # Force query to return nothing
    elif category_filter in ['personal', 'professional']:
        # For specific non-private categories, filter by category AND ensure not private
        query = query.filter_by(category=category_filter)
    else: # 'all' or any other category value
        query = query.filter(BlogPost.category.in_(['personal','professional']))
    # --- End Query Modification ---

    pagination = query.paginate(page=page, per_page=10, error_out=False)
    posts = pagination.items

    return render_template(
      'index.html',
      posts=posts,
      pagination=pagination,
      active_filter=category_filter,
      view_mode=view_mode,
      config=app.config
    )


@app.route('/about')
def about():
    # --- START: Log visit ---
    log_visit(page_title="About Page")
    # --- END: Log visit ---
    personal = AboutSection.query.filter_by(section_type='personal').first()
    professional = AboutSection.query.filter_by(section_type='professional').first()
    return render_template(
        'about.html',
        personal=personal,
        professional=professional,
        config=app.config # Pass config for S3 URL construction in template
    )


@app.route('/blog/<int:post_id>', methods=['GET', 'POST'])
def view_blog(post_id):
    post = BlogPost.query.get_or_404(post_id)
    # --- START: Log visit attempt *before* password checks ---
    log_visit(post_id=post.id, post_title=post.title)
    # --- END: Log visit attempt ---
    should_log_visit = False

    # --- Password checking logic for ANY protected post ---
    if post.password:
        session_key = f'post_{post_id}_access'
        if session.get(session_key):
            should_log_visit = True
        elif request.method == 'POST':
            entered = request.form.get('password','')
            if check_password_hash(post.password, entered):
                session[session_key] = True
                should_log_visit = True
            else:
                flash("Incorrect password.", "error")
                return render_template('password_prompt.html', post=post, config=app.config, csrf_token=generate_csrf())
        else:
            return render_template('password_prompt.html', post=post, config=app.config, csrf_token=generate_csrf())
    else:
        should_log_visit = True



    return render_template('blog_view.html', post=post, config=app.config)


# --- Admin Routes ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # If already logged in, go to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Look up the admin in the database
        admin = Admin.query.filter_by(username=username).first()

        # Verify password
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin) # Use Flask-Login to manage session
            flash('Login successful!', 'success')
            # Redirect to the originally requested page or dashboard
            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    # Use generate_csrf() if using manual tokens in the template
    return render_template('login.html', csrf_token=generate_csrf())


@app.route('/admin/logout')
@login_required # Ensure user must be logged in to log out
def admin_logout():
    logout_user() # Use Flask-Login's logout function
    # Clear post access session keys if implemented
    keys_to_remove = [key for key in session if key.startswith('post_') and key.endswith('_access')]
    for key in keys_to_remove:
        session.pop(key, None)
    # Clear private section access key
    session.pop('private_section_access', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/admin')
@login_required # Use decorator for consistent auth check
def admin_dashboard():
    # Removed manual session check

    posts = BlogPost.query.order_by(BlogPost.date_posted.desc()).all()

    try:
        visitor_logs = VisitorLog.query.order_by(VisitorLog.visit_time.desc()).limit(40).all()
    except Exception as e:
        app.logger.error(f"Error fetching visitor logs: {e}")
        visitor_logs = []
        flash("Could not retrieve visitor logs.", "error")

    profile_pic_filename = SiteSetting.get("profile_pic_filename") # This is now an S3 Key

    return render_template(
        'admin_dashboard.html',
        posts=posts,
        visitor_logs=visitor_logs,
        profile_pic_filename=profile_pic_filename,
        config=app.config, # Pass config for S3 URLs,
        csrf_token=generate_csrf()
    )

@app.route('/admin/blog/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_blog(post_id):
    """Deletes a blog post and associated S3 images."""
    post = BlogPost.query.get(post_id)
    if not post:
        flash(f"Post with ID {post_id} not found.", "error")
        return redirect(url_for('admin_dashboard'))

    s3_bucket = app.config.get('S3_BUCKET')
    image_keys_to_delete = []
    if post.image_filenames:
        image_keys_to_delete = [key.strip() for key in post.image_filenames.split(',') if key.strip()]

    try:
        # Delete related visitor logs first (optional, but good practice)
        VisitorLog.query.filter_by(blog_post_id=post.id).delete()

        # Delete the post object from the database session
        db.session.delete(post)

        # Commit the database changes (post and logs deletion)
        db.session.commit()
        flash(f'Post "{post.title}" and associated logs deleted successfully!', 'success')

        # Now, attempt to delete images from S3 AFTER successful DB commit
        if s3_bucket and image_keys_to_delete:
            app.logger.info(f"Attempting to delete S3 images for post {post_id}: {image_keys_to_delete}")
            failures = []
            for key in image_keys_to_delete:
                if not delete_file_from_s3(s3_bucket, key):
                    failures.append(key)
            if failures:
                flash(f'Post deleted, but failed to delete these S3 images: {", ".join(failures)}. Please check S3 manually.', 'warning')
                app.logger.error(f'S3 delete failed for keys {failures} after deleting post {post_id}')

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting post "{post.title}": {e}', 'error')
        app.logger.error(f"Error deleting post {post_id}: {e}")

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required # Use decorator for consistent auth check
def admin_settings():
    # Removed manual session check

    s3_bucket = app.config.get('S3_BUCKET') # Use .get() for safety
    if not s3_bucket:
         flash('S3 Bucket not configured in application settings.', 'error')
         return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        try:
            # Handle profile picture removal
            if 'remove_profile_pic' in request.form:
                key_to_remove = SiteSetting.get("profile_pic_filename")
                if key_to_remove:
                    # Commit DB change *before* S3 deletion
                    SiteSetting.set("profile_pic_filename", None)
                    db.session.commit()
                    # Now delete from S3
                    if delete_file_from_s3(s3_bucket, key_to_remove):
                        flash('Profile picture removed.', 'info')
                    else:
                        # DB change already committed, S3 failed - log this issue
                        flash(f'Profile picture removed from database, but failed to delete from S3: "{key_to_remove}". Please check S3 manually.', 'warning')
                        app.logger.error(f'S3 delete failed for {key_to_remove} after DB commit.')
                else:
                    flash('No profile picture to remove.', 'info')

            # Handle profile picture upload
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and file.filename and allowed_file(file.filename):
                    # Create a unique object name
                    # object_name = f"profile/{datetime.utcnow().timestamp()}_{secure_filename(file.filename)}"
                    # Upload the new picture
                    uploaded_key = upload_file_to_s3(file, s3_bucket)
                    if uploaded_key:
                        old_key = SiteSetting.get("profile_pic_filename")
                        # Stage DB update
                        SiteSetting.set("profile_pic_filename", uploaded_key)
                        db.session.commit() # Commit DB change first
                        flash('Profile picture updated.', 'success')
                        # Delete old file AFTER successful upload and DB commit
                        if old_key and old_key != uploaded_key:
                            delete_file_from_s3(s3_bucket, old_key)
                    else:
                        flash('Failed to upload profile picture to S3.', 'error')

                elif file and file.filename and not allowed_file(file.filename):
                    flash(f'Invalid file type for profile picture: "{file.filename}". Allowed: {", ".join(ALLOWED_EXTENSIONS)}.', 'error')

            # Handle visibility toggle
            show_pic_val = 'true' if 'show_profile_pic' in request.form else 'false'
            # Only commit if the value changed or other changes happened
            if SiteSetting.get("show_profile_pic") != show_pic_val:
                 SiteSetting.set("show_profile_pic", show_pic_val)
                 db.session.commit() # Commit visibility change

        except Exception as e:
            db.session.rollback()
            flash(f'Error saving settings: {e}', 'error')
            app.logger.exception(f"Error saving admin settings: {e}")

        # Redirect back to settings page after POST
        return redirect(url_for('admin_settings'))

    # GET Request
    current_pic_key = SiteSetting.get("profile_pic_filename")
    show_pic = SiteSetting.get_bool("show_profile_pic")
    # Use generate_csrf() if using manual tokens in the template
    return render_template(
        'admin_settings.html',
        current_pic=current_pic_key, # Pass S3 key
        show_pic=show_pic,
        config=app.config, # Pass config for S3 URL
        csrf_token=generate_csrf()
    )


@app.route('/admin/blog/new', methods=['GET', 'POST'])
@app.route('/admin/blog/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required # Use decorator
def edit_blog(post_id=None):
    """Create or edit a blog post (supports 'personal', 'professional', 'private')."""
    post = BlogPost.query.get(post_id) if post_id else None
    form = BlogForm(obj=post) # Pass obj=post for pre-population on edit
    s3_bucket = app.config.get('S3_BUCKET')

    # Handle removal of an existing image via separate form submission (if not using form.validate_on_submit for removal)
    if request.method == 'POST' and 'remove_image' in request.form:
        remove_key = request.form.get('remove_image')
        if remove_key and post and post.image_filenames:
            keys = [k.strip() for k in post.image_filenames.split(',') if k.strip()]
            if remove_key in keys:
                keys.remove(remove_key)
                post.image_filenames = ','.join(keys) or None # Update DB field
                # Commit DB change *before* deleting from S3
                try:
                    db.session.commit()
                    # Now attempt S3 deletion
                    if delete_file_from_s3(s3_bucket, remove_key):
                        flash('Image removed.', 'info')
                    else:
                        flash(f'Image removed from post, but S3 deletion failed for {remove_key}.', 'warning')
                        app.logger.error(f'S3 delete failed for blog image {remove_key} after DB commit.')
                except Exception as e:
                     db.session.rollback()
                     flash(f'Database error removing image: {e}', 'error')
                     app.logger.error(f"DB error removing blog image key {remove_key}: {e}")

                # Redirect back to the edit page to show changes
                return redirect(url_for('edit_blog', post_id=post.id))
            else:
                flash('Image key not found for this post.', 'warning')
        else:
            flash('Post or image key not specified for removal.', 'error')
        # Redirect back if removal logic was triggered but failed conditions
        return redirect(url_for('edit_blog', post_id=post.id) if post_id else url_for('edit_blog'))

    # On main form submit (Save Post), validate and save
    # This block now only handles saving content and adding NEW images
    if form.validate_on_submit():
        try:
            is_new_post = post is None
            post = post or BlogPost()
            form.populate_obj(post) # Populate basic fields like title, body, date, category, is_private

            # Handle password protection on any post
            if form.password.data:
                # If the user filled in a password, (re-)hash it
                post.password = generate_password_hash(form.password.data)
            elif post.password and not is_new_post:
                # Editing: no new password ⇒ keep the existing hash
                pass
            else:
                # No password provided on a new post (or cleared on edit) ⇒ no protection
                post.password = None


            # Handle NEW image uploads
            new_keys = []
            if s3_bucket and form.images.data:
                for file in form.images.data:
                    if file and file.filename and allowed_file(file.filename):
                        # obj_name = f"blog_images/{datetime.utcnow().timestamp()}_{secure_filename(file.filename)}"
                        key = upload_file_to_s3(file, s3_bucket)
                        if key:
                            new_keys.append(key)
                        else:
                            flash(f"Failed to upload {file.filename}.", "error")
                    elif file and file.filename:
                         flash(f'Skipped blog upload: Invalid file type for "{file.filename}".', 'warning')

            # Append new keys to existing ones
            if new_keys:
                existing_keys = post.image_filenames.split(',') if post.image_filenames else []
                # Filter empty strings that might result from split/join
                all_keys = filter(None, [k.strip() for k in existing_keys + new_keys])
                post.image_filenames = ','.join(all_keys) or None

            db.session.add(post)
            db.session.commit()
            flash('Post saved successfully!', 'success')
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
             db.session.rollback()
             flash(f'Error saving post: {e}', 'error')
             app.logger.exception("Error saving blog post")

    # GET request or validation failed
    # Pass config needed for displaying existing images
    return render_template('blog_edit.html', form=form, post=post, config=app.config)


@app.route('/admin/about', methods=['GET', 'POST'])
@login_required # Use decorator
def edit_about():
    # Removed manual session check

    s3_bucket = app.config.get('S3_BUCKET')
    if not s3_bucket:
         flash('S3 Bucket not configured.', 'error')
         return redirect(url_for('admin_dashboard'))

    personal = AboutSection.query.filter_by(section_type='personal').first()
    professional = AboutSection.query.filter_by(section_type='professional').first()

    # --- START: Image Removal Logic ---
    if request.method == 'POST' and 'remove_image' in request.form:
        key_to_remove = request.form.get('remove_image')
        section_type = request.form.get('section_type') # 'personal' or 'professional'
        section_object = None

        if section_type == 'personal': section_object = personal
        elif section_type == 'professional': section_object = professional

        if section_object and section_object.image_filenames and key_to_remove:
            keys = [k.strip() for k in section_object.image_filenames.split(',') if k.strip()]
            if key_to_remove in keys:
                keys.remove(key_to_remove)
                section_object.image_filenames = ','.join(keys) or None # Update field
                # Commit DB change *before* deleting from S3
                try:
                    db.session.commit()
                    # Now attempt S3 deletion
                    if delete_file_from_s3(s3_bucket, key_to_remove):
                        flash(f'Image "{key_to_remove}" removed from {section_type} section.', 'info')
                    else:
                         flash(f'Image removed from {section_type} section, but S3 deletion failed for {key_to_remove}.', 'warning')
                         app.logger.error(f'S3 delete failed for about image {key_to_remove} after DB commit.')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Database error removing image key: {e}', 'error')
                    app.logger.error(f"DB error removing about image key {key_to_remove}: {e}")
            else:
                 flash(f'Image key "{key_to_remove}" not found in {section_type} section.', 'warning')
        else:
            flash('Could not find section or image key to remove.', 'error')

        # Redirect back to the edit page after attempting removal
        return redirect(url_for('edit_about'))
    # --- END: Image Removal Logic ---


    # --- Existing POST logic for saving content and uploading NEW images ---
    # This runs if the POST request was NOT for removing an image
    if request.method == 'POST':
        try:
            # --- Update Personal Section ---
            if not personal:
                personal = AboutSection(section_type='personal')
                db.session.add(personal)
            personal.content = request.form.get('personal_content', '')

            # Handle Personal Image Uploads (Adding New)
            new_personal_keys = []
            if 'personal_images' in request.files:
                 for image in request.files.getlist('personal_images'):
                      if image and image.filename and allowed_file(image.filename):
                        #    object_name = f"about_personal/{datetime.utcnow().timestamp()}_{secure_filename(image.filename)}"
                           uploaded_key = upload_file_to_s3(image, s3_bucket)
                           if uploaded_key: new_personal_keys.append(uploaded_key)
                           else: flash(f'Failed to upload personal image "{image.filename}".', 'error')
                      elif image and image.filename: flash(f'Skipped personal upload: Invalid file type for "{image.filename}".', 'warning')
            # Append new keys if any were uploaded
            if new_personal_keys:
                current_personal_keys = personal.image_filenames.split(',') if personal.image_filenames else []
                personal.image_filenames = ','.join(filter(None, [k.strip() for k in current_personal_keys + new_personal_keys])) or None


            # --- Update Professional Section ---
            if not professional:
                professional = AboutSection(section_type='professional')
                db.session.add(professional)
            professional.content = request.form.get('professional_content', '')

            # Handle Professional Image Uploads (Adding New)
            new_prof_keys = []
            if 'professional_images' in request.files:
                 for image in request.files.getlist('professional_images'):
                      if image and image.filename and allowed_file(image.filename):
                        #    object_name = f"about_professional/{datetime.utcnow().timestamp()}_{secure_filename(image.filename)}"
                           uploaded_key = upload_file_to_s3(image, s3_bucket)
                           if uploaded_key: new_prof_keys.append(uploaded_key)
                           else: flash(f'Failed to upload professional image "{image.filename}".', 'error')
                      elif image and image.filename: flash(f'Skipped professional upload: Invalid file type for "{image.filename}".', 'warning')
            # Append new keys if any were uploaded
            if new_prof_keys:
                 current_prof_keys = professional.image_filenames.split(',') if professional.image_filenames else []
                 professional.image_filenames = ','.join(filter(None, [k.strip() for k in current_prof_keys + new_prof_keys])) or None

            # --- Commit ---
            db.session.commit()
            flash('About sections updated successfully!', 'success')
            return redirect(url_for('admin_dashboard')) # Redirect after successful save

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating About sections: {e}', 'error')
            app.logger.exception("Error updating About sections")
        # If save fails, fall through to render template again

    # GET request or save failed
    # Use generate_csrf() if using manual tokens in the template
    return render_template(
        'about_edit.html',
        personal=personal,
        professional=professional,
        config=app.config,
        csrf_token=generate_csrf()
    )


# --- START: New Password Management Route ---
@app.route('/admin/passwords', methods=['GET', 'POST'])
@login_required
def admin_password_management():
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'change_admin_pw':
                new_password = request.form.get('new_admin_password')
                if new_password:
                    # Get the Admin object for the currently logged-in user
                    admin_user = Admin.query.get(current_user.id)
                    if admin_user:
                        admin_user.password_hash = generate_password_hash(new_password)
                        db.session.commit()
                        flash('Admin password updated successfully.', 'success')
                    else:
                         # Should not happen if logged in via Flask-Login user_loader
                        flash('Admin user not found.', 'error')
                else:
                    flash('New admin password cannot be empty.', 'error')

            elif action == 'change_section_pw':
                new_password = request.form.get('new_section_password')
                if new_password:
                    hashed_password = generate_password_hash(new_password)
                    # Use the SiteSetting helper method
                    SiteSetting.set('private_section_password', hashed_password)
                    db.session.commit()
                    flash('Private section password updated successfully.', 'success')
                else:
                    flash('New section password cannot be empty.', 'error')

            elif action == 'change_post_pw':
                post_id_str = request.form.get('post_id') # Get as string first
                new_password = request.form.get('new_post_password')
                if post_id_str and post_id_str.isdigit() and new_password:
                    post_id = int(post_id_str)
                    post = BlogPost.query.get(post_id)
                    if post and post.is_private:
                        print(post.password)
                        post.password = generate_password_hash(new_password)
                                                # --- Add Logging Here ---
                        new_hash = generate_password_hash(new_password)
                        print(f"--- DEBUG: Attempting to save hash for post {post_id}: {new_hash}") # Or use app.logger.info
                        # --- End Logging ---
                        db.session.commit()
                        print(post.password)
                        flash(f'Password for post "{post.title}" updated successfully.', 'success')
                    elif post and not post.is_private:
                         flash(f'Post "{post.title}" is not private. Password not changed.', 'warning')
                    else:
                        flash(f'Private post with ID {post_id} not found.', 'error')
                elif not post_id_str or not post_id_str.isdigit():
                    flash('Please select a valid post.', 'error')
                else: # No new_password
                    flash('New post password cannot be empty.', 'error')

            else:
                flash('Invalid action specified.', 'error')

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'error')
            app.logger.error(f"Password management error: {e}")

        # Redirect back to the same page to show flash messages/updated state
        return redirect(url_for('admin_password_management'))

    # GET Request: Fetch private posts for the dropdown
    private_posts = BlogPost.query.filter_by(is_private=True).order_by(BlogPost.date_posted.desc()).all()
    # Use generate_csrf() if using manual tokens in the template
    return render_template('admin_password_management.html', private_posts=private_posts, csrf_token=generate_csrf())
# --- END: New Password Management Route ---


# --- Context Processor ---
@app.context_processor
def inject_global_vars():
    # Fetch profile picture S3 key globally (if needed elsewhere, otherwise keep in specific routes)
    profile_pic_filename = SiteSetting.get("profile_pic_filename") # S3 key
    show_profile_pic = SiteSetting.get_bool("show_profile_pic", default=False)

    return {
        'now': datetime.utcnow(),
        'site_name': "Mohamed Matoug", # Or load from config/SiteSetting
        'profile_pic_filename_global': profile_pic_filename,
        'show_profile_pic_global': show_profile_pic,
        'config': app.config # Make config accessible globally in templates if needed
    }

# --- Error Handlers ---
@app.errorhandler(403)
def forbidden(e):
    # Render a specific 403 template or use the 404 template with a custom message
    # return render_template("errors/403.html"), 403
    # Correcting the 404 template's content is better than showing wrong text here.
    return render_template("404.html", error_code=403, error_message="Forbidden - You don't have permission to access this page."), 403

@app.errorhandler(404)
def page_not_found(e):
    # You might want to pass info to the template
    return render_template("404.html", error_code=404, error_message="Page Not Found"), 404

@app.errorhandler(405)
def method_not_allowed(e):
    # Render a specific 405 template or use the 404 template with a custom message
    # return render_template("errors/405.html"), 405
    return render_template("404.html", error_code=405, error_message="Method Not Allowed"), 405