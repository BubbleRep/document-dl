"""download documents from an IMAP account/server"""

import imaplib
import os
import email
import email.policy
import re
import unicodedata
import tempfile
import hashlib

import click

import docdl
import docdl.util


# blacklist a few words for filenames and extensions that you usually don't want
# @todo make them configurable
blacklist_filename = ['widerruf', 'bild', 'agb']
blacklist_extension = ['.vcf']


def slugify(value, allow_unicode=True):
    """
    Taken from https://github.com/django/django/blob/master/django/utils/text.py
    Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
    dashes to single dashes. Remove characters that aren't alphanumerics,
    underscores, or hyphens. Convert to lowercase. Also strip leading and
    trailing whitespace, dashes, and underscores.
    """

    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize('NFKC', value)
    else:
        value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
    value = re.sub(r'[^\w\s\.-]', '', value.lower())
    value = re.sub(r'[-\s]+', '-', value)
    return value


def get_hash(file):
    """calculate hash of files to identify duplicates"""
    if os.path.exists(file):
        block_size = 65536
        file_hash = hashlib.sha256()
        with open(file, 'rb') as file_handle:
            file_bytes = file_handle.read(block_size)
            while len(file_bytes) > 0:
                file_hash.update(file_bytes)
                file_bytes = file_handle.read(block_size)
    else:
        return None
    return file_hash.hexdigest()


def compare_hash(fileone, filetwo):
    """helping function to compare 2 hashes"""
    hashone = get_hash(fileone)
    hashtwo = get_hash(filetwo)
    if hashone == hashtwo:
        return True
    return False


def get_new_filename(filename, counter=0):
    """
    create new file name if original one already exists, by appending a counter as
    long as necessary
    """
    filepre, extension = os.path.splitext(filename)
    fileorg = filepre
    if counter > 0:
        file = f'{fileorg}_{counter}{extension}'
    else:
        file = f'{fileorg}{extension}'
    if os.path.exists(file):
        if counter > 1:
            i = 1
            while i < counter:
                if compare_hash(file, f'{fileorg}_{i}{extension}'):
                    return False
                i += 1
        return get_new_filename(filename, counter + 1)
    return file


def parse_address(mail_string):
    """extract email address from string"""
    match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', mail_string)
    return match.group(0)


def parse_issuer(mail_string):
    """remove some common general names"""
    if 'Amazon Marketplace' in mail_string:
        return slugify(re.search(r'^(.*) - Amazon Marketplace', mail_string).group(1))
    if 'Amazon Payments' in mail_string:
        return slugify(re.search(r'^(.*) - Amazon Payments', mail_string).group(1))
    return slugify('.'.join(parse_address(mail_string)[parse_address(mail_string).index('@') + 1:].split('.')[:-1]))


class Mutex(click.Option):
    """
    might be a useful addon to add to the __init__.py to have it available for all plugins
    """

    # source: https://stackoverflow.com/questions/44247099/click-command-line-interfaces-make-options-required-if-other-optional-option-is by Stephen Rauch
    def __init__(self, *args, **kwargs):
        self.not_required_if: list = kwargs.pop("not_required_if")

        assert self.not_required_if, "'not_required_if' parameter required"
        kwargs["help"] = (kwargs.get("help", "") + "Option is mutually exclusive with " + ", "
                          .join(self.not_required_if) + ".").strip()
        super(Mutex, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        current_opt: bool = self.name in opts
        for mutex_opt in self.not_required_if:
            if mutex_opt in opts:
                if current_opt:
                    raise click.UsageError("Illegal usage: '" + str(self.name) +
                                           "' is mutually exclusive with " + str(mutex_opt) + ".")
                self.prompt = None
        return super(Mutex, self).handle_parse_result(ctx, opts, args)


class IMAP(docdl.WebPortal):
    """download documents from an IMAP account"""

    def __init__(self, login_id, password, useragent=None, arguments=None):
        super().__init__(
            login_id=login_id,
            password=password,
            arguments=arguments,
            useragent=None
        )
        self.mail = None
        if arguments['email_searchexp'] is None and (
           arguments['email_search'] is not None and
           arguments['email_field'] is not None):
            self.searchexp = '(' + arguments['email_field'] + ' ' + arguments['email_search'] + ')'
        else:
            self.searchexp = arguments['email_searchexp']

    def login(self):
        """authenticate"""
        try:
            self.mail = imaplib.IMAP4_SSL(self.arguments['server'], self.arguments['port'])
            status, msg = self.mail.login(self.login_id, self.password)
            self.mail.select("inbox", readonly=True)
            return self.mail
        except imaplib.IMAP4.error as ex:
            print(ex)
        return False

    def logout(self):
        return self.mail.logout()

    def documents(self):
        """fetch list of documents"""
        # remove double spaces, since they are incompatible with the imap search terms
        searchstring = f'(X-GM-RAW has:attachment {self.searchexp})'
        searchstring = searchstring.replace('  ', ' ').replace('( ', '(').replace(' )', ')')
        status, data = self.mail.search(None, None, searchstring)
        if status == 'OK':
            mail_ids = data[0].split()
        for num in mail_ids:
            status, data = self.mail.fetch(num, 'BODY.PEEK[]')
            mail = email.message_from_bytes(data[0][1], policy=email.policy.default)
            attachments = 0
            for att in mail.iter_attachments():
                if any(word.lower() in att.get_filename().lower() for word in blacklist_filename):
                    continue
                if any(word.lower() in os.path.splitext(att.get_filename())[1].lower()
                       for word in blacklist_extension):
                    continue
                attachments += 1
            if attachments > 0:
                i = 0
                issuer = parse_issuer(mail['Reply-To'])
                if mail['Reply-To'] is None or (
                   parse_address(mail['Reply-To']) == parse_address(mail['From'])):
                    issuer = parse_issuer(mail['From'])
                for att in mail.iter_attachments():
                    if any(word.lower() in att.get_filename().lower()
                           for word in blacklist_filename):
                        continue
                    if any(word.lower() in os.path.splitext(att.get_filename())[1].lower()
                           for word in blacklist_extension):
                        continue
                    filename = att.get_filename()
                    if attachments > 1:
                        filename, file_extension = os.path.splitext(att.get_filename())
                        filename = f"{filename}_{i+1}{file_extension}"
                    yield docdl.Document(
                        # not sure if the uri is correct for imap
                        # @todo fix uri for imap
                        url=f'imap://{self.login_id}@{self.arguments["server"]}'
                            ':{self.arguments["port"]}/INBOX/{mail["Message-ID"]}',
                        attributes={
                         'Message-ID': mail['Message-ID'],
                         'date': email.utils.parsedate_to_datetime(mail['Date']),
                         'issuer': issuer,
                         'filename': os.path.join(issuer, filename),
                         'aid': i
                        }
                    )
                    i += 1
            else:
                continue
        return []

    def download(self, document):
        """download document"""
        # don't attempt download without url
        if "Message-ID" in document.attributes:
            if document.attributes['Message-ID'] is not None:
                filename = document.attributes['filename']
        filename = self.download_with_imaplib(document)
        return filename

    def download_with_imaplib(self, document):
        """
        @todo add a database function to make sure files are not downloaded
        twice, otherwise files are downloaded eachtime if they are moved
        from targed dir
        """
        msgid = document.attributes['Message-ID']
        status, mails = self.mail.search(None, f'HEADER Message-ID {msgid}')
        for mail in mails:
            status, mail = self.mail.fetch(mail, "(RFC822)")
            mail = email.message_from_bytes(mail[0][1], policy=email.policy.default)
            aid = 0
            for att in mail.iter_attachments():
                if aid == document.attributes['aid']:
                    filepre, extension = os.path.splitext(document.attributes['filename'])
                    path = os.path.dirname(document.attributes['filename'])
                    os.makedirs(path, exist_ok=True)
                    with tempfile.NamedTemporaryFile(suffix=extension, delete=False,
                                                     dir=os.getcwd()) as temp_file:
                        temp_file.write(att.get_content())
                        epoch = int(document.attributes['date'].strftime('%s'))
                        os.utime(temp_file.name, (epoch, epoch))
                        if compare_hash(document.attributes['filename'], temp_file.name):
                            if os.path.exists(temp_file.name):
                                os.remove(temp_file.name)
                            return document.attributes['filename']
                        new_filename = get_new_filename(f'{filepre}{extension}', 0)
                        if new_filename is False:
                            os.remove(temp_file.name)
                        else:
                            os.rename(temp_file.name, new_filename)
                        return temp_file.name
                aid += 1
        return ''


@click.command()
@click.option(
    "-s",
    "--server",
    prompt=True,
    required=True,
    hide_input=False,
    envvar="DOCDL_IMAP_SERVER",
    show_envvar=True,
    help="IMAP Server"
)
@click.option(
    "-p",
    "--port",
    default=993,
    prompt=False,
    hide_input=False,
    envvar="DOCDL_IMAP_PORT",
    show_envvar=True,
    help="IMAP Port"
)
@click.option(
    "--email-field",
    prompt=False,
    hide_input=False,
    envvar="DOCDL_IMAP_SEARCHFIELD",
    show_envvar=True,
    help="IMAP search in email field",
    cls=Mutex,
    not_required_if=["email_searchtuple"]
)
@click.option(
    "--email-search",
    prompt=False,
    hide_input=False,
    envvar="DOCDL_IMAP_SEARCHTERM",
    show_envvar=True,
    help="IMAP Email search term",
    cls=Mutex,
    not_required_if=["email_searchtuple"]
)
@click.option(
    "--email-searchexp",
    default="[]",
    prompt=False,
    hide_input=False,
    envvar="DOCDL_IMAP_SEARCHEXP",
    show_envvar=True,
    help="IMAP Email search expression "
         "e.g. DOCDL_IMAP_SEARCHEXP=\"(OR (SUBJECT rechnung) (SUBJECT invoice)\" "
         "searches for all mails which have attachment (hard coded) and either "
         "rechnung or invoice in their subject (hint: there is no AND-operator, "
         "it's the default behavior)",
    cls=Mutex,
    not_required_if=["email_search", "email_field"]
)
@click.pass_context
# pylint: disable = C0103
def imap(ctx, *args, **kwargs):
    """
    download imap account (attachments) \n
    requires one of the following:\n
      --email-field and --email-search\n
      --email-searchexp\n
    """
    docdl.cli.run(ctx, IMAP)
