#!/bin/python
from io import BytesIO
from threading import Thread, Event
from os.path import basename, splitext, join, isdir, exists, getsize, expanduser
from os import makedirs, remove
from copy import copy
from lxml import etree
import pycurl
import logging
import traceback

try:
    # python 3
    from urllib.parse import urlencode
except ImportError:
    # python 2
    from urllib import urlencode


class PugPigPyLoginFailed(Exception):
    """
    Username or password are invalid.
    """
    pass


class PugPigPyNotAuthorized(Exception):
    """
    The current subscription does not allow the requested operation.
    """
    pass


class PugPigPyNotLoggedIn(Exception):
    """
    The operation requested requires login.
    """
    pass


class PugPigPyNoConnection(Exception):
    """
    Internet connection appears to be missing or failed.
    """
    pass


class PugPigPyRequestFailed(Exception):
    """
    Generic failure in HTTP API request.
    """
    pass


class Report(Thread):
    """
    An object that starts a thread calling the `report_function` with the
    result of the `get_current` and `get_total` functions.
    It stops when the stop_event is set.
    """

    def __init__(self, stop_event, report_function, get_current, get_total):
        Thread.__init__(self)
        self._rf = report_function
        self._gc = get_current
        self._gt = get_total
        self._stopped = stop_event

    def run(self):
        while not self._stopped.wait(0.5):
            if self._rf:
                self._rf(self._gc(), self._gt())


class ProgressBytesIO(BytesIO):
    """
    A overloaded version of BytesIO that periodically reports on progress
    given a total amount of bytes to be written and a progress_function
    function to be called when called in a python `with` environment.

    """

    def __init__(self, *args, **kwargs):
        """
        Extracts two arguments from call and then initializes BytesIO.

        Args:
            tot_size (int): the (supposed) total size of the data to be written.
            progress_function (function): the function to be periodically called.
                                          it must accept two arguments: current and total.
        Returns:
            None
        """
        self.tot_size = kwargs.pop('tot_size')
        self.progress_function = kwargs.pop('progress_function')
        super(ProgressBytesIO, self).__init__(*args, **kwargs)

    def __enter__(self):
        """
        Start reporting thread
        """
        self.stopFlag = Event()
        thread = Report(self.stopFlag, self.progress_function,
                        self.tell, lambda: self.tot_size)
        thread.start()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """
        Stop reporting thread when leaving `with` environment.
        """
        self.stopFlag.set()
        if exc_type is not None:
            traceback.print_exception(exc_type, exc_value, tb)
        return True


class PugPigPy(object):
    """
    This class partially implements the APIs described here:

    https://pugpig.zendesk.com/hc/en-us/articles/201239965-Server-Side-Security-Interfaces

    It is supposed to provide support to electronic published 
    for platforms not currently supported by PugPig apps, namely Librem
    phones and Sailfish OS.
    """

    # Some user agent. Better not hardcode in the future.
    USER_AGENT = "PugpigNetwork 2.7.2, 2.3.0 (SM-G960U, Android 28)"
    USER_AGENT = "PugpigNetwork 2.7.2, 2.3.0 (Sony D6543, Android 23)"
    USER_AGENT = "PugpigNetwork 2.7.2, 2.3.0 (Sony G3313, Android 24)"
    USER_AGENT = "PugpigNetwork 2.7.2, 2.3.0 (HUAWEI VNS-L23, Android 24)"
    USER_AGENT = "PugpigNetwork 2.7.2, 2.3.0 (LG M700, Android 24)"


    def __init__(self, main_site, cache_dir, progress_callback=None):
        """
        Initialization of PugPigPy.

        Args:
            main_site (str): the main page to access PugPig APIs.
            cache_dir (str): where to store tokens, cookies and edition files.
            progress_callback (function): a function to be periodically called on long downloads.

        Returns:
            None
        """
        self._main_site = main_site
        self._cache_dir = cache_dir
        self._progress_cb = progress_callback

        # Status
        self._token = ""
        self._editions = []

        # Check if token present
        try:
            with open(join(self._cache_dir, 'token'), 'r') as f:
                self._token = f.read()
        except:
            logging.debug("Token not found")

        try:
            with open(join(self._cache_dir, 'opds.xml'), 'rb') as f:
                self._editions = self._parse_opds(f.read())
        except:
            logging.debug("No OPDS file")

        self._collect_cached_files()

    def _set_standard_curl_options(self, c, buffer, timeout=100):
        """
        Default options for curl requests.

        Args:
            c (pycurl.Curl): the pyculr object to configure.
            buffer (BytesIO): the object used to store the response.
            timeout (int): timeout for request, in seconds.

        Returns:
            None
        """
        c.setopt(pycurl.USERAGENT, self.USER_AGENT)
        c.setopt(pycurl.TIMEOUT, timeout)
        #c.setopt(pycurl.LOW_SPEED_TIME, 45)
        #c.setopt(pycurl.LOW_SPEED_LIMIT, 5)

        c.setopt(pycurl.FOLLOWLOCATION, 1)

        c.setopt(pycurl.SSL_VERIFYPEER, False)
        c.setopt(pycurl.SSL_VERIFYHOST, False)
        c.setopt(pycurl.COOKIEFILE, join(self._cache_dir, 'cookies.dat'))
        c.setopt(pycurl.COOKIEJAR, join(self._cache_dir, 'cookies.dat'))

        c.setopt(pycurl.WRITEFUNCTION, buffer.write)

        if pycurl.version_info()[7]:
            c.setopt(pycurl.ENCODING, 'gzip,deflate')

    def _perform_request(self, c):
        """
        Perform http request and raises appropriate errors

        Args:
            c (pycurl.Curl): the pyculr object to configure.

        Returns:
            None

        Raises:
            PugPigPyNoConnection, PugPigPyRequestFailed
        """
        status = -1
        try:
            c.perform()
            status = c.getinfo(pycurl.RESPONSE_CODE)
            c.close()
        except:
            raise PugPigPyNoConnection from None
        if status != 200:
            raise PugPigPyRequestFailed

    @property
    def login_required(self):
        """
        Tells whether the user should perform a login.
        This happens on first access or when token expires.
        """
        return self._token == ''

    def update_content(self):
        """
        Collects available editions and store the result.
        Also checks editions that are already available in cache.
        """
        logging.debug('update_content')

        c = pycurl.Curl()
        buffer = BytesIO()
        self._set_standard_curl_options(c, buffer)

        c.setopt(c.URL, "https://"+self._main_site+"/?feed=opds")

        self._perform_request(c)

        resp = buffer.getvalue()

        self._editions = self._parse_opds(resp)

        with open(join(self._cache_dir, 'opds.xml'), 'wb') as f:
            f.write(resp)

        self._collect_cached_files()

    @property
    def editions(self):
        """
        Returns a copy of the list containing the available editions.
        Each element contains a dictionary with information.
        The element index should be used to interact with the library,
        for example to start a download or extract the PDF.
        """
        return copy(self._editions)

    def login(self, username, password):
        """
        Login with username and password and store the access token.
        Once the token is saved, login is no longer required.

        Args:
            username (str): the username.
            password (str): the password.

        Returns:
            A list of three elements:
            1. True if successful
            2. The status
            3. A message.

        The details of status and message is given here: https://pugpig.zendesk.com/hc/en-us/articles/202782503-Security-API-Specification
        """

        c = pycurl.Curl()
        buffer = BytesIO()
        self._set_standard_curl_options(c, buffer)

        c.setopt(c.URL, "https://"+self._main_site+"/sign_in/")

        post_data = {'email':   username,
                     'password': password
                     }
        postfields = urlencode(post_data)

        c.setopt(pycurl.POST, True)
        c.setopt(pycurl.POSTFIELDS, postfields)

        c.perform()
        resp = buffer.getvalue()
        c.close()

        r = self._parse_token(resp)

        self._update_token(r['token'])

        return (self._token != '', r['status'], r['message'])

    def _update_token(self, tk):
        """
        Set internal token variable and save it to file.
        Removes invalid token if tk is none.

        Args:
            tk (str or None): the token.

        Returns:
            None
        """
        if tk:
            self._token = tk
            with open(join(self._cache_dir, 'token'), 'w') as f:
                f.write(self._token)
        else:
            remove(join(self._cache_dir, 'token'))

    @staticmethod
    def _parse_token(response):
        """
        Parses a Token of this form:

        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><token>TgZYHHYLPxgmZCiJCEs3V1Oq0WUS3jWufU8fEjrIrOJfH37e82jSM39zhTzvfaid3ZQC2dmUpHezUu5OSqg6gCDat5vCV83vfSd1LYZzFwJC0HwB6GOnuQUZdAZlIydz</token>'

        return a dictionary containing the token, if present, otherwise and empty string,
        the status and an info message.
        """
        res = etree.fromstring(response)
        if res.tag == 'token':
            return {'token': res.text, 'status': 'ok', 'message': ''}
        elif res.tag == 'error':
            return {'token': '',
                    'status':  res.attrib['status'],
                    'message': res.attrib['message'] if 'message' in res.keys() else ''}

    @staticmethod
    def _parse_subscription_status(response):
        """
        Parse XML containing subscription status response.
        """
        res = etree.fromstring(response)
        return {'state':   res.attrib['state'],
                'message': res.attrib['message'] if 'message' in res.keys() else '',
                'name':    res[0].find('name').text if res.getchildren() else '',
                'expires': res[0].find('expires').text if res.getchildren() else ''}

    def verify_subscription(self):
        """
        Checks status of current subscription.
        Returns:
            A dictionary with 4 keys: 'state', 'message', 'name', 'expires'.
        """

        if self._token == "":
            raise PugPigPyNotLoggedIn

        c = pycurl.Curl()
        buffer = BytesIO()
        self._set_standard_curl_options(c, buffer)

        c.setopt(c.URL, "https://"+self._main_site+"/verify_subscription/")

        post_data = {'token': self._token}
        postfields = urlencode(post_data)

        c.setopt(pycurl.POST, True)
        c.setopt(pycurl.POSTFIELDS, postfields)

        c.perform()
        resp = buffer.getvalue()
        c.close()

        r = self._parse_subscription_status(resp)

        return r

    def renew_token(self):
        """
        Request new token our current token is expired.

        http://YOURSITE/renew_token/?token=OLD_TOKEN
        """

        if self._token == '':
            raise PugPigPyNotLoggedIn

        c = pycurl.Curl()
        buffer = BytesIO()
        self._set_standard_curl_options(c, buffer)

        c.setopt(c.URL, "https://"+self._main_site+"/renew_token/")

        post_data = {'token': self._token}
        postfields = urlencode(post_data)

        c.setopt(pycurl.POST, True)
        c.setopt(pycurl.POSTFIELDS, postfields)

        c.perform()
        resp = buffer.getvalue()
        c.close()

        r = self._parse_token(resp)

        self._update_token(r['token'])

        return (self._token != '', r['status'], r['message'])

    @staticmethod
    def _parse_opds(response):
        """
        Parses OPDS XML file.
        """
        res = etree.fromstring(response)

        editions_list = []

        ns = {'atom': 'http://www.w3.org/2005/Atom'}
        for v in res.findall('atom:entry', ns):

            title = v.find('atom:title', ns).text
            id = v.find('atom:id', ns).text
            published = v.find('atom:published', ns).text

            links = v.findall('atom:link', ns)
            for link in links:
                if link.attrib['type'] == 'image/jpg':
                    cover = link.attrib['href']
                elif link.attrib['type'] == 'application/pugpigpkg+xml':
                    if link.attrib['rel'] != 'alternate':
                        manifest = link.attrib['href']

            editions_list.append({'title': title,
                                  'id': id,
                                  'published': published,
                                  'cover': cover,
                                  'manifest': manifest,
                                  'files': []
                                  }
                                 )

        return editions_list

    def _get_edition_credentials(self, token, edition):
        """
        Parse credentials to download an edition with http request.
        """
        c = pycurl.Curl()
        buffer = BytesIO()
        self._set_standard_curl_options(c, buffer)

        c.setopt(c.URL, "https://"+self._main_site+"/edition_credentials/")

        post_data = {'token': token,
                     'product_id': edition['id']
                     }
        postfields = urlencode(post_data)

        c.setopt(pycurl.POST, True)
        c.setopt(pycurl.POSTFIELDS, postfields)

        self._perform_request(c)
        resp = buffer.getvalue()

        return self._parse_edition_credentials(resp)

    @staticmethod
    def _parse_edition_credentials(response):
        """
        Parse XML response and extracts username and password to access
        edition's files.
        """
        res = etree.fromstring(response)
        r = {'userid': '', 'password': '', 'error': '', 'message': ''}

        if (res.find('userid') != None) and (res.find('password') != None):
            r['userid'] = res.find('userid').text
            r['password'] = res.find('password').text
        else:
            r['status'] = res.find('error').attrib['status']
            r['message'] = res.find('error').attrib['message']
        return r

    @staticmethod
    def _parse_manifest(response):
        """
        Parse XML Manifest of the edition, where file names and location is indicated.
        """
        res = etree.fromstring(response)
        pkgs = []
        for part in res.findall('part'):

            pkgs.append({'src': part.attrib['src'],
                         'size': int(part.attrib['size']),
                         'name': part.attrib['name']
                         })
        return pkgs

    def _download_edition(self, eid):
        """
        Actually download edition. 
        Should only be called when not present in cache.
        """
        edition = self._editions[eid]
        edition_path = join(self._cache_dir, edition['id'])

        if isdir(edition_path):
            logging.warning('Overwriting '+edition_path)

        r = self._get_edition_credentials(self._token, edition)

        if r['userid']:
            username, password = r['userid'], r['password']
        else:
            raise PugPigPyNotAuthorized

        manifest = edition['manifest']
        title = edition['title']

        # Check if dir exists
        if not exists(edition_path):
            makedirs(edition_path)

        c = pycurl.Curl()
        buffer = BytesIO()
        self._set_standard_curl_options(c, buffer, timeout=40)

        c.setopt(c.URL, 'https://' + self._main_site + manifest)

        c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
        c.setopt(pycurl.USERPWD, username + ':' + password)

        self._perform_request(c)
        resp = buffer.getvalue()

        with open(join(edition_path, 'manifest.xml'), 'wb') as f:
            f.write(resp)

        pkgs = self._parse_manifest(resp)

        downloads = []

        for pkg in pkgs:

            link = pkg['src']
            bname = basename(link)

            with ProgressBytesIO(tot_size=pkg['size'], progress_function=self._progress_cb) as b:
                c = pycurl.Curl()
                self._set_standard_curl_options(c, b, timeout=100)

                c.setopt(c.URL, 'https://' + self._main_site + link)

                c.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
                c.setopt(pycurl.USERPWD, username + ':' + password)

                self._perform_request(c)

            b.seek(0)
            with open(join(edition_path, bname), 'wb') as f:
                f.write(b.read())

            downloads.append(bname)

            # Check dimensions
            if getsize(join(edition_path, bname)) != pkg['size']:
                logger.debug('Download probably invalid')

        return downloads

    def get_edition(self, eid):
        """
        Download the edition requested.
        eid : edition index in the list given by the edition property.
        """
        logging.debug('get_edition ( {} )'.format(eid))

        if not self._edition_cached(eid):
            if self._token != '':
                self._editions[eid]['files'] = self._download_edition(eid)
            else:
                raise PugPigPyNotLoggedIn

    def _check_package(self, where):
        """
        Checks if a downloaded edition is valid.
        """

        logging.debug('_check_package ( '+where+')')

        if exists(join(where, 'manifest.xml')):
            with open(join(where, 'manifest.xml'), 'rb') as f:
                try:
                    pkgs = self._parse_manifest(f.read())
                except:
                    logging.debug('Invalid pakcage manifest.')
                    return []

                # Check if there's everything
                is_complete = True

                files = []
                for pkg in pkgs:
                    bname = basename(pkg['src'])
                    if not exists(join(where, bname)):
                        logging.debug(
                            'File '+join(where, bname)+' is missing.')
                        is_complete = False
                        break
                    # Check dimensions
                    if getsize(join(where, bname)) != pkg['size']:
                        logging.debug('Dimension do not match: ', getsize(
                            join(where, bname)),  pkg['size'])
                        is_complete = False
                        break

                    files.append(bname)
                return files if is_complete else []

        return []

    def _edition_cached(self, eid):
        """
        Checks if an edition is present in cache.

        Args:
            eid (int): The edition id.

        Returns:
            bool: The return value. True for success, False otherwise.
        """

        edition = self._editions[eid]

        edition_path = join(self._cache_dir, edition['id'])

        if isdir(edition_path):
            logging.debug('Checking '+edition_path)
            self._editions[eid]['files'] = self._check_package(edition_path)

            if self._editions[eid]['files'] != []:
                return True
        return False

    def _collect_cached_files(self):
        """
        Collects all cached editions in the internal _edition list.
        """
        for i, edition in enumerate(self._editions):
            edition_path = join(self._cache_dir, edition['id'])

            if isdir(edition_path):
                self._editions[i]['files'] = self._check_package(edition_path)

    def extract_pdf(self, eid, where=None):
        """
        Extract PDF file from edition if present.
        """
        from zipfile import ZipFile

        edition = self._editions[eid]
        edition_path = join(self._cache_dir, edition['id'])

        if not where:
            where = edition_path

        edition = self._editions[eid]

        edition_name = edition['title'].replace(' ', '-') + '.pdf'

        for file_name in edition['files']:
            with ZipFile(join(edition_path, file_name), 'r') as zip:
                for zipped_file in zip.namelist():
                    _, ext = splitext(zipped_file)
                    if ext == '.pdf':
                        logging.debug('Saving')
                        with open(join(where, edition_name), 'wb') as f:
                            f.write(zip.read(zipped_file))
        return join(where, edition_name)


if __name__ == "__main__":
    """
    Here I provide a very simple CLI to explain how to use the library.
    """
    import os
    import getpass
    # Python2 / Python 3
    try:
        input = raw_input
    except NameError:
        pass

    # Function reporting download progress.
    def progress(download_d, download_t):
        """
        This progress function will show current and total size on screen
        """
        import time
        import sys

        sys.stdout.write("\rDownloading {} of {}".format(
            download_d, download_t))
        sys.stdout.flush()

    # Create a new PugPigPy object and set cache in ~/ilManifeto
    ppp = PugPigPy('ilmanifesto.it', join(
        expanduser("~"), 'ilManifesto'), progress)

    # Retrieve current contenr
    ppp.update_content()

    # If it's the first time we try to access, request login credentials
    if ppp.login_required:
        USERNAME = input('Username: ')
        PASSWORD = getpass.getpass('Password: ')
        ppp.login(USERNAME, PASSWORD)

    # Check status of our subscription and react accordingly
    r = ppp.verify_subscription()

    if r['state'] == 'stale':
        ppp.renew_token()
    elif r['state'] == 'inactive':
        ppp.login(USERNAME, PASSWORD)
    else:
        logger.warning("Current state is: " + r['state'])

    # List editions
    for i, e in enumerate(ppp.editions):
        print(i, e['title'], e['files'] != [])
        if i >= 10:
            break

    # Select issue based on previously printed list
    i = input('Which one? ')
    try:
        i = int(i)
    except:
        print('Invalid, should be a number from 0 to 9')

    # Retrieve selected edition either from cache or web
    ppp.get_edition(i)

    # Extract PDF file and show it
    pdf_file = ppp.extract_pdf(i)
    if input('Open PDF? ').lower() in ('y', 'yes', 'ok', 'sure'):
        os.system("xdg-open "+pdf_file)
