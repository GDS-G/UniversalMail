"""Microsoft Graph and Gmail mailbox adapters. Read, send and organization."""
import base64
from email import message_from_bytes
from email.policy import default
from urllib.parse import quote

from .provider_http import authorized, ProviderError
from .mime import compose_message

GRAPH = "https://graph.microsoft.com/v1.0/me"
GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"


def folders(account):
    if account["kind"] == "outlook":
        result = authorized(account, "GET", GRAPH + "/mailFolders", params={"$top": 100})
        return [{"id": x["id"], "name": x["displayName"], "total": x.get("totalItemCount")}
                for x in result.get("value", [])]
    result = authorized(account, "GET", GMAIL + "/labels")
    return [{"id": x["id"], "name": x["name"], "type": x.get("type")} for x in result.get("labels", [])]


def messages(account, folder, limit):
    if account["kind"] == "outlook":
        url = GRAPH + "/mailFolders/" + quote(folder, safe="") + "/messages"
        result = authorized(account, "GET", url, params={"$top": limit, "$select": "id,subject,from,toRecipients,receivedDateTime,isRead,hasAttachments"})
        return [{"id": x["id"], "subject": x.get("subject"),
                 "from": x.get("from", {}).get("emailAddress", {}).get("address"),
                 "date": x.get("receivedDateTime"), "is_read": x.get("isRead"),
                 "has_attachments": x.get("hasAttachments")} for x in result.get("value", [])]
    result = authorized(account, "GET", GMAIL + "/messages",
                        params={"labelIds": folder, "maxResults": limit})
    return result.get("messages", [])


def message(account, message_id):
    if account["kind"] == "outlook":
        return authorized(account, "GET", GRAPH + "/messages/" + quote(message_id, safe=""),
                          params={"$select": "id,subject,from,toRecipients,ccRecipients,body,receivedDateTime,isRead,hasAttachments,internetMessageId"})
    return authorized(account, "GET", GMAIL + "/messages/" + quote(message_id, safe=""),
                      params={"format": "full"})


def raw(account, message_id):
    if account["kind"] == "outlook":
        return authorized(account, "GET", GRAPH + "/messages/" + quote(message_id, safe="") + "/$value")
    result = authorized(account, "GET", GMAIL + "/messages/" + quote(message_id, safe=""),
                        params={"format": "raw"})
    value = result.get("raw", "")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def send(account, payload):
    raw_bytes, recipients = compose_message(
        account["email"], [str(x) for x in payload.to], payload.subject, payload.text,
        payload.html, [str(x) for x in payload.cc], [str(x) for x in payload.bcc],
        [x.model_dump() for x in payload.attachments], payload.in_reply_to, payload.references)
    if account["kind"] == "outlook":
        authorized(account, "POST", GRAPH + "/sendMail", data=base64.b64encode(raw_bytes),
                   headers={"Content-Type": "text/plain"})
        return {"accepted_by_provider": True, "delivered": "unverified"}
    result = authorized(account, "POST", GMAIL + "/messages/send",
                        json_body={"raw": base64.urlsafe_b64encode(raw_bytes).decode().rstrip("=")})
    return {"accepted_by_provider": True, "message_id": result.get("id"), "delivered": "unverified"}


def set_read(account, message_id, read):
    if account["kind"] == "outlook":
        authorized(account, "PATCH", GRAPH + "/messages/" + quote(message_id, safe=""),
                   json_body={"isRead": read})
        return {"updated": True}
    action = "removeLabelIds" if read else "addLabelIds"
    authorized(account, "POST", GMAIL + "/messages/" + quote(message_id, safe="") + "/modify",
               json_body={action: ["UNREAD"]})
    return {"updated": True}


def move(account, message_id, destination):
    if account["kind"] == "outlook":
        result = authorized(account, "POST", GRAPH + "/messages/" + quote(message_id, safe="") + "/move",
                            json_body={"destinationId": destination})
        return {"moved": True, "new_message_id": result.get("id"),
                "spam_reclassification": False, "sender_allowlisted": False}
    msg = message(account, message_id)
    labels = [x for x in msg.get("labelIds", []) if x in ("INBOX", "SPAM", "TRASH")]
    authorized(account, "POST", GMAIL + "/messages/" + quote(message_id, safe="") + "/modify",
               json_body={"removeLabelIds": labels, "addLabelIds": [destination]})
    return {"moved": True, "spam_reclassification": False, "sender_allowlisted": False}


def mark_not_spam(account, message_id):
    if account["kind"] != "gmail":
        raise ProviderError(501, "Native not-spam reclassification not implemented for this provider")
    authorized(account, "POST", GMAIL + "/messages/" + quote(message_id, safe="") + "/modify",
               json_body={"removeLabelIds": ["SPAM"], "addLabelIds": ["INBOX"]})
    return {"message_not_spam": True, "sender_allowlisted": False}


def allowlist_sender(account, sender):
    if account["kind"] != "gmail":
        raise ProviderError(501, "Persistent Safe Senders configuration is not available through this adapter")
    # Gmail filters have a 'neverSpam' option. Verify by listing filters after creation.
    created = authorized(account, "POST", GMAIL + "/settings/filters",
                         json_body={"criteria": {"from": sender}, "action": {"neverSpam": True}})
    filter_id = created.get("id")
    if not filter_id:
        raise ProviderError(502, "Gmail did not confirm creation of a safe-sender filter")
    confirmed = authorized(account, "GET", GMAIL + "/settings/filters/" + quote(filter_id, safe=""))
    if not confirmed.get("action", {}).get("neverSpam") or confirmed.get("criteria", {}).get("from") != sender:
        raise ProviderError(502, "Safe sender filter was not verified")
    return {"sender_allowlisted": True, "sender": sender, "filter_id": filter_id,
            "scope": "Gmail neverSpam filter", "existing_messages_changed": False}
