import base64
import mimetypes
import uuid
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from pwd_manager import db
from pwd_manager.models import Collection, Document, DocumentAttachment
from pwd_manager.utils import escape_like, safe_error_message
from pwd_manager.utils.auth import get_user_encryption_key
from pwd_manager.utils.crypto import (
    decrypt_binary,
    decrypt_data,
    encrypt_binary,
    encrypt_data,
)

library_bp = Blueprint("library", __name__)


def _delete_attachment_file(attachment):
    """Remove the on-disk encrypted file for an attachment."""
    storage_path = (
        Path(current_app.config["ATTACHMENTS_DIR"]) / attachment.storage_filename
    )
    if storage_path.exists():
        storage_path.unlink()


def _delete_document_attachments(document):
    """Remove all on-disk attachment files for a document."""
    for attachment in list(document.attachments):
        _delete_attachment_file(attachment)


def _ensure_general_collection(user_id):
    """Return the user's General collection, creating it if missing."""
    collection = Collection.query.filter_by(user_id=user_id, name="General").first()
    if not collection:
        collection = Collection(user_id=user_id, name="General")
        db.session.add(collection)
        db.session.commit()
    return collection


def _sort_collections(collections):
    """Place General first, then sort the rest alphabetically by name."""
    general = [c for c in collections if c.name == "General"]
    others = sorted([c for c in collections if c.name != "General"], key=lambda c: c.name.lower())
    return general + others


@library_bp.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    general = _ensure_general_collection(user_id)

    collections = Collection.query.filter_by(user_id=user_id).all()
    collections = _sort_collections(collections)

    active_id = request.args.get("collection_id", type=int) or general.id
    active_collection = Collection.query.filter_by(id=active_id, user_id=user_id).first()
    if not active_collection:
        active_collection = general

    search_query = request.args.get("search", "").lower()
    tag_filter = request.args.get("tag", "")

    documents = Document.query.filter_by(
        user_id=user_id, is_draft=False, collection_id=active_collection.id
    )

    if search_query:
        safe_query = escape_like(search_query)
        documents = documents.filter(
            (Document.title.ilike(f"%{safe_query}%", escape="\\"))
            | (Document.tags.ilike(f"%{safe_query}%", escape="\\"))
        )

    if tag_filter:
        safe_tag = escape_like(tag_filter)
        documents = documents.filter(
            Document.tags.ilike(f"%{safe_tag}%", escape="\\")
        )

    documents = documents.order_by(Document.updated_at.desc()).all()

    all_tags = set()
    for doc in documents:
        if doc.tags:
            all_tags.update(tag.strip() for tag in doc.tags.split(","))

    collection_counts = {
        coll.id: Document.query.filter_by(
            user_id=user_id, is_draft=False, collection_id=coll.id
        ).count()
        for coll in collections
    }

    return render_template(
        "library/index.html",
        collections=collections,
        active_collection=active_collection,
        documents=documents,
        all_tags=sorted(all_tags),
        search_query=search_query,
        tag_filter=tag_filter,
        collection_counts=collection_counts,
    )


@library_bp.route("/add", methods=["GET", "POST"])
def add_document():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    encryption_key = get_user_encryption_key()
    if not encryption_key:
        flash("Error retrieving encryption key", "error")
        return redirect(url_for("library.index"))

    collection_id = request.args.get("collection_id", type=int)
    if collection_id:
        collection = Collection.query.filter_by(
            id=collection_id, user_id=user_id
        ).first()
        if not collection:
            flash("Collection not found", "error")
            return redirect(url_for("library.index"))
    else:
        collection = _ensure_general_collection(user_id)

    if request.method == "POST":
        document_id = request.form.get("document_id")
        document = Document.query.get_or_404(document_id)

        if document.user_id != user_id or not document.is_draft:
            flash("Unauthorized or invalid document", "error")
            return redirect(url_for("library.index"))

        title = request.form.get("title")
        content = request.form.get("content", "")
        if not title:
            flash("Title is required", "error")
            return render_template(
                "library/document_form.html",
                document=document,
                content=content,
                form_action=url_for("library.add_document"),
                cancel_url=url_for("library.cancel_document", doc_id=document.id),
                page_title="Add New Document",
            )

        document.title = title
        document.tags = request.form.get("tags")
        document.encrypted_content = (
            encrypt_data(encryption_key, content) if content else None
        )
        document.is_draft = False
        document.updated_at = datetime.now(UTC)
        db.session.commit()

        flash("Document saved successfully!", "success")
        return redirect(url_for("library.view_document", doc_id=document.id))

    # Clean up any leftover drafts for this user before creating a new one
    old_drafts = Document.query.filter_by(user_id=user_id, is_draft=True).all()
    for draft in old_drafts:
        _delete_document_attachments(draft)
        db.session.delete(draft)
    db.session.commit()

    draft = Document(
        user_id=user_id,
        collection_id=collection.id,
        title="",
        encrypted_content=None,
        is_draft=True,
    )
    db.session.add(draft)
    db.session.commit()

    return render_template(
        "library/document_form.html",
        document=draft,
        content="",
        form_action=url_for("library.add_document"),
        cancel_url=url_for("library.cancel_document", doc_id=draft.id),
        page_title="Add New Document",
    )


@library_bp.route("/cancel/<int:doc_id>")
def cancel_document(doc_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    document = Document.query.get_or_404(doc_id)
    if document.user_id != session["user_id"] or not document.is_draft:
        flash("Unauthorized or invalid document", "error")
        return redirect(url_for("library.index"))

    _delete_document_attachments(document)
    db.session.delete(document)
    db.session.commit()

    return redirect(url_for("library.index"))


@library_bp.route("/<int:doc_id>")
def view_document(doc_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    document = Document.query.get_or_404(doc_id)
    if document.user_id != session["user_id"] or document.is_draft:
        flash("Unauthorized or invalid document", "error")
        return redirect(url_for("library.index"))

    encryption_key = get_user_encryption_key()
    if not encryption_key:
        flash("Error retrieving encryption key", "error")
        return redirect(url_for("library.index"))

    try:
        content = (
            decrypt_data(encryption_key, document.encrypted_content)
            if document.encrypted_content
            else ""
        )
        return render_template(
            "library/view_document.html",
            document=document,
            content=content,
        )
    except Exception:
        current_app.logger.exception(f"Error decrypting document {doc_id}")
        flash("Error decrypting document content", "error")
        return redirect(url_for("library.index"))


@library_bp.route("/edit/<int:doc_id>", methods=["GET", "POST"])
def edit_document(doc_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    document = Document.query.get_or_404(doc_id)
    if document.user_id != session["user_id"] or document.is_draft:
        flash("Unauthorized or invalid document", "error")
        return redirect(url_for("library.index"))

    encryption_key = get_user_encryption_key()
    if not encryption_key:
        flash("Error retrieving encryption key", "error")
        return redirect(url_for("library.index"))

    if request.method == "POST":
        title = request.form.get("title")
        if not title:
            flash("Title is required", "error")
            return redirect(url_for("library.edit_document", doc_id=doc_id))

        content = request.form.get("content", "")
        document.title = title
        document.tags = request.form.get("tags")
        document.encrypted_content = (
            encrypt_data(encryption_key, content) if content else None
        )
        document.updated_at = datetime.now(UTC)
        db.session.commit()

        flash("Document updated successfully!", "success")
        return redirect(url_for("library.view_document", doc_id=doc_id))

    try:
        content = (
            decrypt_data(encryption_key, document.encrypted_content)
            if document.encrypted_content
            else ""
        )
    except Exception:
        current_app.logger.exception(f"Error decrypting document {doc_id}")
        content = ""

    return render_template(
        "library/document_form.html",
        document=document,
        content=content,
        form_action=url_for("library.edit_document", doc_id=doc_id),
        cancel_url=url_for("library.view_document", doc_id=doc_id),
        page_title="Edit Document",
    )


@library_bp.route("/delete/<int:doc_id>", methods=["POST"])
def delete_document(doc_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    document = Document.query.get_or_404(doc_id)
    if document.user_id != session["user_id"]:
        flash("Unauthorized access", "error")
        return redirect(url_for("library.index"))

    _delete_document_attachments(document)
    db.session.delete(document)
    db.session.commit()

    flash("Document deleted successfully", "success")
    return redirect(
        url_for(
            "library.index",
            collection_id=document.collection_id if document.collection_id else None,
        )
    )


@library_bp.route("/collection/add", methods=["POST"])
def add_collection():
    """Create a new collection for the current user."""
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    name = request.form.get("name", "").strip()
    if not name:
        flash("Collection name is required", "error")
        return redirect(url_for("library.index"))

    if Collection.query.filter_by(user_id=user_id, name=name).first():
        flash("A collection with that name already exists", "error")
        return redirect(url_for("library.index"))

    collection = Collection(user_id=user_id, name=name)
    db.session.add(collection)
    db.session.commit()
    flash("Collection created", "success")
    return redirect(url_for("library.index", collection_id=collection.id))


@library_bp.route("/collection/<int:coll_id>/rename", methods=["POST"])
def rename_collection(coll_id):
    """Rename an existing collection."""
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    collection = Collection.query.filter_by(
        id=coll_id, user_id=user_id
    ).first_or_404()

    if collection.name == "General":
        flash("The General collection cannot be renamed", "error")
        return redirect(url_for("library.index"))

    new_name = request.form.get("name", "").strip()
    if not new_name:
        flash("Collection name is required", "error")
        return redirect(url_for("library.index", collection_id=collection.id))

    if (
        new_name == "General"
        or Collection.query.filter(
            Collection.id != collection.id,
            Collection.user_id == user_id,
            Collection.name == new_name,
        ).first()
    ):
        flash("A collection with that name already exists", "error")
        return redirect(url_for("library.index", collection_id=collection.id))

    collection.name = new_name
    collection.updated_at = datetime.now(UTC)
    db.session.commit()
    flash("Collection renamed", "success")
    return redirect(url_for("library.index", collection_id=collection.id))


@library_bp.route("/collection/<int:coll_id>/delete", methods=["POST"])
def delete_collection(coll_id):
    """Delete a collection and all of its documents and attachments."""
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    collection = Collection.query.filter_by(
        id=coll_id, user_id=user_id
    ).first_or_404()

    if collection.name == "General":
        flash("The General collection cannot be deleted", "error")
        return redirect(url_for("library.index", collection_id=collection.id))

    for doc in list(collection.documents):
        _delete_document_attachments(doc)
    db.session.delete(collection)
    db.session.commit()
    flash("Collection deleted", "success")
    return redirect(url_for("library.index"))


# ============== Library Attachment Routes ==============


@library_bp.route("/attachment/upload/<int:doc_id>", methods=["POST"])
def upload_attachment(doc_id):
    """Upload and encrypt a file attachment for a library document."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    document = Document.query.get_or_404(doc_id)
    if document.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized access"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not DocumentAttachment.allowed_file(file.filename):
        return (
            jsonify(
                {
                    "error": f'File type not allowed. Allowed types: {", ".join(DocumentAttachment.ALLOWED_EXTENSIONS)}'
                }
            ),
            400,
        )

    file_content = file.read()
    if len(file_content) > DocumentAttachment.MAX_FILE_SIZE:
        return (
            jsonify(
                {
                    "error": f"File too large. Maximum size is {DocumentAttachment.MAX_FILE_SIZE // (1024 * 1024)}MB"
                }
            ),
            400,
        )

    encryption_key = get_user_encryption_key()
    if not encryption_key:
        return jsonify({"error": "Error retrieving encryption key"}), 500

    try:
        encrypted_content = encrypt_binary(encryption_key, file_content)
        storage_filename = f"{uuid.uuid4()}.enc"
        storage_path = Path(current_app.config["ATTACHMENTS_DIR"]) / storage_filename
        storage_path.write_bytes(encrypted_content)

        mime_type = (
            file.content_type
            or mimetypes.guess_type(file.filename)[0]
            or "application/octet-stream"
        )

        attachment = DocumentAttachment(
            document_id=doc_id,
            original_filename=file.filename,
            mime_type=mime_type,
            file_size=len(file_content),
            storage_filename=storage_filename,
        )

        db.session.add(attachment)
        db.session.commit()

        return jsonify(
            {
                "success": True,
                "attachment": {
                    "id": attachment.id,
                    "filename": attachment.original_filename,
                    "size": attachment.file_size,
                    "mime_type": attachment.mime_type,
                },
            }
        )
    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": safe_error_message(f"Error uploading file: {exc}")}), 500


@library_bp.route("/attachment/upload-clipboard/<int:doc_id>", methods=["POST"])
def upload_clipboard_image(doc_id):
    """Upload an image from the clipboard (base64 data) for a library document."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    document = Document.query.get_or_404(doc_id)
    if document.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized access"}), 403

    data = request.get_json()
    if not data or "image_data" not in data:
        return jsonify({"error": "No image data provided"}), 400

    image_data = data["image_data"]
    filename = data.get("filename", "clipboard_image.png")

    if "," in image_data:
        header, base64_data = image_data.split(",", 1)
        if "image/png" in header:
            mime_type = "image/png"
            if not filename.endswith(".png"):
                filename = (
                    filename.rsplit(".", 1)[0] + ".png"
                    if "." in filename
                    else filename + ".png"
                )
        elif "image/jpeg" in header or "image/jpg" in header:
            mime_type = "image/jpeg"
            if not filename.endswith((".jpg", ".jpeg")):
                filename = (
                    filename.rsplit(".", 1)[0] + ".jpg"
                    if "." in filename
                    else filename + ".jpg"
                )
        elif "image/gif" in header:
            mime_type = "image/gif"
            if not filename.endswith(".gif"):
                filename = (
                    filename.rsplit(".", 1)[0] + ".gif"
                    if "." in filename
                    else filename + ".gif"
                )
        elif "image/webp" in header:
            mime_type = "image/webp"
            if not filename.endswith(".webp"):
                filename = (
                    filename.rsplit(".", 1)[0] + ".webp"
                    if "." in filename
                    else filename + ".webp"
                )
        else:
            mime_type = "image/png"
    else:
        base64_data = image_data
        mime_type = "image/png"

    try:
        file_content = base64.b64decode(base64_data)
    except Exception:
        return jsonify({"error": "Invalid base64 image data"}), 400

    if len(file_content) > DocumentAttachment.MAX_FILE_SIZE:
        return (
            jsonify(
                {
                    "error": f"Image too large. Maximum size is {DocumentAttachment.MAX_FILE_SIZE // (1024 * 1024)}MB"
                }
            ),
            400,
        )

    encryption_key = get_user_encryption_key()
    if not encryption_key:
        return jsonify({"error": "Error retrieving encryption key"}), 500

    try:
        encrypted_content = encrypt_binary(encryption_key, file_content)
        storage_filename = f"{uuid.uuid4()}.enc"
        storage_path = Path(current_app.config["ATTACHMENTS_DIR"]) / storage_filename
        storage_path.write_bytes(encrypted_content)

        attachment = DocumentAttachment(
            document_id=doc_id,
            original_filename=filename,
            mime_type=mime_type,
            file_size=len(file_content),
            storage_filename=storage_filename,
        )

        db.session.add(attachment)
        db.session.commit()

        return jsonify(
            {
                "success": True,
                "attachment": {
                    "id": attachment.id,
                    "filename": attachment.original_filename,
                    "size": attachment.file_size,
                    "mime_type": attachment.mime_type,
                },
            }
        )
    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": safe_error_message(f"Error uploading clipboard image: {exc}")}), 500


@library_bp.route("/attachment/download/<attachment_id>")
def download_attachment(attachment_id):
    """Download and decrypt a library document attachment."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    attachment = DocumentAttachment.query.get_or_404(attachment_id)
    document = Document.query.get_or_404(attachment.document_id)

    if document.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized access"}), 403

    encryption_key = get_user_encryption_key()
    if not encryption_key:
        return jsonify({"error": "Error retrieving encryption key"}), 500

    try:
        storage_path = (
            Path(current_app.config["ATTACHMENTS_DIR"]) / attachment.storage_filename
        )
        if not storage_path.exists():
            return jsonify({"error": "Attachment file not found"}), 404

        encrypted_content = storage_path.read_bytes()
        decrypted_content = decrypt_binary(encryption_key, encrypted_content)

        return send_file(
            BytesIO(decrypted_content),
            mimetype=attachment.mime_type,
            as_attachment=True,
            download_name=secure_filename(attachment.original_filename),
        )
    except Exception as exc:
        return jsonify({"error": safe_error_message(f"Error downloading file: {exc}")}), 500


@library_bp.route("/attachment/delete/<attachment_id>", methods=["POST"])
def delete_attachment(attachment_id):
    """Delete a library document attachment."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    attachment = DocumentAttachment.query.get_or_404(attachment_id)
    document = Document.query.get_or_404(attachment.document_id)

    if document.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized access"}), 403

    try:
        _delete_attachment_file(attachment)
        db.session.delete(attachment)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": safe_error_message(f"Error deleting attachment: {exc}")}), 500


@library_bp.route("/attachment/list/<int:doc_id>")
def list_attachments(doc_id):
    """List all attachments for a library document."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    document = Document.query.get_or_404(doc_id)
    if document.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized access"}), 403

    attachments = [
        {
            "id": att.id,
            "filename": att.original_filename,
            "size": att.file_size,
            "mime_type": att.mime_type,
            "created_at": att.created_at.isoformat(),
        }
        for att in document.attachments
    ]

    return jsonify({"attachments": attachments})


@library_bp.route("/attachment/preview/<attachment_id>")
def preview_attachment(attachment_id):
    """Return attachment content for preview (base64 JSON or inline PDF)."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    attachment = DocumentAttachment.query.get_or_404(attachment_id)
    document = Document.query.get_or_404(attachment.document_id)

    if document.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized access"}), 403

    encryption_key = get_user_encryption_key()
    if not encryption_key:
        return jsonify({"error": "Error retrieving encryption key"}), 500

    try:
        storage_path = (
            Path(current_app.config["ATTACHMENTS_DIR"]) / attachment.storage_filename
        )
        if not storage_path.exists():
            return jsonify({"error": "Attachment file not found"}), 404

        encrypted_content = storage_path.read_bytes()
        decrypted_content = decrypt_binary(encryption_key, encrypted_content)

        if attachment.mime_type == "application/pdf":
            return send_file(
                BytesIO(decrypted_content),
                mimetype=attachment.mime_type,
                as_attachment=False,
                download_name=secure_filename(attachment.original_filename),
            )

        content_base64 = base64.b64encode(decrypted_content).decode("utf-8")
        return jsonify(
            {
                "success": True,
                "content": content_base64,
                "mime_type": attachment.mime_type,
                "filename": attachment.original_filename,
            }
        )
    except Exception as exc:
        return jsonify({"error": safe_error_message(f"Error viewing attachment: {exc}")}), 500
