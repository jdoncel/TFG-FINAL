from simplegmail import Gmail

gmail = Gmail()

def checkEmailUnRead():
    messages = gmail.get_unread_inbox()
    i=[]
    for message in messages:
        i.append(message.id)
    return i
def checkEmailStored():
    messages = gmail.get_starred_messages()
    i = []
    for message in messages:
        i.append(message.id)
    return i
def senderCheck(id):
    messages = gmail.get_unread_inbox()
    for message in messages:
        if message.id ==id:
            senderCadena=(message.sender[message.sender.find(("<")):message.sender.find((">"))])
            #senderCadena="j.dＡncelgalan99@gmail.com"
            for i in senderCadena:
                if (ord(i)<255 and ord(i)>32):
                    pass
                else:
                    #return message.sender[message.sender.find(("<")):message.sender.find((">"))]
                    return message.sender
    return True
def checkEmailHasWeb(id):
    messages = gmail.get_unread_inbox()
    for message in messages:
        if message.id == id:
            #webCheck = (message.sender[message.sender.find(("<")):message.sender.find((">"))])
            if(message.plain[message.plain.find(("http")):message.plain.find("/n")] !='' or message.plain[message.plain.find(("http")):message.plain.find("\n")] !='' or message.plain[message.plain.find(("http")):message.plain.find(" ")] !=''):
                if message.plain[message.plain.find(("http")):message.plain.find(" ")] !='':
                    return (message.plain[message.plain.find(("http")):message.plain.find(" ")])
                if message.plain[message.plain.find(("http")):message.plain.find(" ")] !='/n':
                    return (message.plain[message.plain.find(("http")):message.plain.find("/n")])
                if message.plain[message.plain.find(("http")):message.plain.find(" ")] !='\n':
                    return (message.plain[message.plain.find(("http")):message.plain.find("\n")])
    return True

def checkEmailhasFile(id):
    messages = gmail.get_unread_inbox()
    for message in messages:
        if message.id == id:
            if message.attachments:
                for attm in message.attachments:
                    return id
    return True
