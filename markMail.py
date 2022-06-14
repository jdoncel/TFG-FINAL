from simplegmail import Gmail

gmail = Gmail()

def markSpam(id):
    messages = gmail.get_unread_inbox()
    for message in messages:
        if id in message.sender :
            message.mark_as_spam()
            return True
    return False

def markSpamWeb(id):
    messages = gmail.get_unread_inbox()
    for message in messages:
        if id ==message.id:
            message.mark_as_spam()
            return True
    return False