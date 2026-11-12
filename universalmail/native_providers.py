"""Microsoft Graph/Gmail mail adapters; provider state is not spam-training proof."""
import base64
from urllib.parse import quote, urlsplit

from .provider_http import authorized, ProviderError
from .mime import compose_message

GRAPH = "https://graph.microsoft.com/v1.0/me"
GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"


def _page_url(base, cursor):
    if cursor is None:
        return base
    u, b = urlsplit(cursor), urlsplit(base)
    if (u.scheme, u.netloc, u.path) != (b.scheme, b.netloc, b.path) or u.fragment:
        raise ProviderError(400, "Page cursor does not belong to this resource")
    return cursor


def folders(account, parent=None, cursor=None):
    if account["kind"] == "outlook":
        base = GRAPH + ("/mailFolders/" + quote(parent, safe="") + "/childFolders" if parent else "/mailFolders")
        result = authorized(account, "GET", _page_url(base, cursor),
                            params=None if cursor else {"$top": 100, "includeHiddenFolders": "true"})
        items = [{"id": x["id"], "name": x["displayName"], "total": x.get("totalItemCount"),
                  "child_folder_count": x.get("childFolderCount", 0)} for x in result.get("value", [])]
        return {"items": items, "next_page_token": result.get("@odata.nextLink"), "hierarchy": "children_of_parent"}
    if parent or cursor:
        raise ProviderError(400, "Gmail labels are a flat list and do not accept a parent/cursor")
    result = authorized(account, "GET", GMAIL + "/labels")
    return {"items": result.get("labels", []), "next_page_token": None, "hierarchy": "labels"}


def messages(account, folder, limit, cursor=None):
    if account["kind"] == "outlook":
        base = GRAPH + "/mailFolders/" + quote(folder, safe="") + "/messages"
        result = authorized(account, "GET", _page_url(base, cursor), params=None if cursor else {
            "$top": limit, "$select": "id,subject,from,toRecipients,receivedDateTime,isRead,hasAttachments"})
        return {"items": result.get("value", []), "next_page_token": result.get("@odata.nextLink")}
    params = {"labelIds": folder, "maxResults": limit, "includeSpamTrash": "true"}
    if cursor:
        params["pageToken"] = cursor
    result = authorized(account, "GET", GMAIL + "/messages", params=params)
    return {"items": result.get("messages", []), "next_page_token": result.get("nextPageToken")}


def message(account, message_id):
    if account["kind"] == "outlook":
        return authorized(account, "GET", GRAPH + "/messages/" + quote(message_id, safe=""),
                          params={"$select": "id,subject,from,toRecipients,ccRecipients,body,receivedDateTime,isRead,hasAttachments,internetMessageId"})
    return authorized(account, "GET", GMAIL + "/messages/" + quote(message_id, safe=""), params={"format": "full"})


def raw(account, message_id):
    if account["kind"] == "outlook":
        return authorized(account, "GET", GRAPH + "/messages/" + quote(message_id, safe="") + "/$value")
    result = authorized(account, "GET", GMAIL + "/messages/" + quote(message_id, safe=""), params={"format": "raw"})
    value = result["raw"]
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def send(account, payload):
    raw_bytes, _ = compose_message(account["email"], [str(x) for x in payload.to], payload.subject,
        payload.text, payload.html, [str(x) for x in payload.cc], [str(x) for x in payload.bcc],
        [x.model_dump() for x in payload.attachments], payload.in_reply_to, payload.references,
        include_bcc_header=True)
    if account["kind"] == "outlook":
        authorized(account, "POST", GRAPH + "/sendMail", data=base64.b64encode(raw_bytes), headers={"Content-Type": "text/plain"})
        return {"accepted_by_provider": True, "delivered": "unverified"}
    result = authorized(account, "POST", GMAIL + "/messages/send", json_body={"raw": base64.urlsafe_b64encode(raw_bytes).decode().rstrip("=")})
    return {"accepted_by_provider": True, "message_id": result.get("id"), "delivered": "unverified"}


def set_read(account, message_id, read):
    if account["kind"] == "outlook":
        authorized(account, "PATCH", GRAPH + "/messages/" + quote(message_id, safe=""), json_body={"isRead": read})
    else:
        authorized(account, "POST", GMAIL + "/messages/" + quote(message_id, safe="") + "/modify",
                   json_body={"removeLabelIds" if read else "addLabelIds": ["UNREAD"]})
    return {"updated": True}


def move(account, message_id, destination):
    if account["kind"] == "outlook":
        result = authorized(account, "POST", GRAPH + "/messages/" + quote(message_id, safe="") + "/move", json_body={"destinationId": destination})
        return {"moved": True, "new_message_id": result.get("id"), "spam_reclassification": False, "sender_allowlisted": False}
    msg = message(account, message_id)
    labels = [x for x in msg.get("labelIds", []) if x in ("INBOX", "SPAM", "TRASH") and x != destination]
    authorized(account, "POST", GMAIL + "/messages/" + quote(message_id, safe="") + "/modify",
               json_body={"removeLabelIds": labels, "addLabelIds": [destination]})
    return {"moved": True, "other_labels_preserved": True, "spam_reclassification": False, "sender_allowlisted": False}


def mark_not_spam(account, message_id):
    if account["kind"] != "gmail":
        raise ProviderError(501, "Native not-spam reclassification not implemented for this provider")
    authorized(account, "POST", GMAIL + "/messages/" + quote(message_id, safe="") + "/modify",
               json_body={"removeLabelIds": ["SPAM"], "addLabelIds": ["INBOX"]})
    confirmed = message(account, message_id)
    if "labelIds" not in confirmed or "SPAM" in confirmed["labelIds"] or "INBOX" not in confirmed["labelIds"]:
        raise ProviderError(502, "Message not-spam state was not verified; inspect the mailbox before retrying")
    return {"message_not_spam": True, "sender_allowlisted": False, "spam_training_verified": False}


def allowlist_sender(account, sender):
    if account["kind"] != "gmail":
        raise ProviderError(501, "Persistent Outlook Safe Senders is not implemented; no folder move was substituted")
    desired_criteria, desired_action = {"from": sender}, {"removeLabelIds": ["SPAM"]}
    inventory = authorized(account, "GET", GMAIL + "/settings/filters")
    existing = next((x for x in inventory.get("filter", []) if x.get("criteria") == desired_criteria and x.get("action") == desired_action), None)
    result = existing or authorized(account, "POST", GMAIL + "/settings/filters",
                                   json_body={"criteria": desired_criteria, "action": desired_action})
    filter_id = result.get("id")
    if not filter_id:
        raise ProviderError(502, "Gmail did not confirm a safe-sender filter ID")
    confirmed = authorized(account, "GET", GMAIL + "/settings/filters/" + quote(filter_id, safe=""))
    if confirmed.get("criteria") != desired_criteria or confirmed.get("action") != desired_action:
        raise ProviderError(502, "Safe-sender filter was not verified; inspect filters before retrying")
    return {"sender_allowlisted": True, "sender": sender, "filter_id": filter_id,
            "created": existing is None, "scope": "Gmail never-mark-as-spam filter",
            "existing_messages_changed": False, "block_list_checked": False}
