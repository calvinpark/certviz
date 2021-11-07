from __future__ import annotations

import sys
import os
from datetime import datetime
import re
from abc import ABC, abstractmethod
from simpleshell import ss
from termcolor import colored, cprint
import collections


class CryptoObject(ABC):
    TYPE_X509_PUB = "X509-PUB"
    TYPE_X509_PRV = "X509-PRV"
    TYPE_X509_REQ = "X509-REQ"

    def __init__(self, file_abs: str, file_rel: str, kind: str):
        self.file_abs: str = file_abs
        self.file_rel: str = file_rel
        self.kind: str = kind

    @property
    @classmethod
    @abstractmethod
    def id_begin(cls) -> str:
        pass

    @property
    @classmethod
    @abstractmethod
    def id_end(cls) -> str:
        pass

    def __repr__(self):
        return f"{self.kind} {self.file_abs}"

    @classmethod
    def factory(cls, file_abs, file_rel) -> (CryptoObject, str):
        with open(file_abs, 'rb') as f:
            content = f.read()

            if X509_PUB.is_kind(file_abs, content):
                return X509_PUB(file_abs, file_rel, content), cls.TYPE_X509_PUB

            elif X509_PRV.is_kind(file_abs, content):
                return X509_PRV(file_abs, file_rel, content), cls.TYPE_X509_PRV

            elif X509_REQ.is_kind(file_abs, content):
                return X509_REQ(file_abs, file_rel, content), cls.TYPE_X509_REQ

            else:
                return None, None

    @classmethod
    def is_kind(cls, file_abs: str, file_content: bytes) -> bool:
        id_count = len(str(file_content).split(cls.id_begin)) - 1

        # Not ready for a file with multiple certs yet
        if id_count != 1:
            return False

        return cls.is_valid(file_abs)

    @classmethod
    @abstractmethod
    def is_valid(cls, file_path: str) -> bool:
        pass

    @abstractmethod
    def get_printable_list(self) -> list[str]:
        pass

    @classmethod
    @abstractmethod
    def print_list(cls, objects: list):
        pass


class X509_PUB(CryptoObject):
    id_begin = "-----BEGIN CERTIFICATE-----"
    id_end = "-----END CERTIFICATE-----"

    def __init__(self, file_abs: str, file_rel: str, content: bytes):
        super().__init__(file_abs, file_rel, self.TYPE_X509_PUB)
        self._start_datetime: str = None
        self._end_datetime: str = None
        self._subject: str = None
        self._subject_hash: str = None
        self._issuer: str = None
        self._issuer_hash: str = None
        self._subject_alt_names: list = None
        self._modulus_md5: str = None
        self.is_trusted: bool = None
        self.private_key: X509_PRV = None
        self.issuer_obj: X509_PUB = None
        self.issuee_objs: list[X509_PUB] = list()
        self.request: X509_REQ = None

        self.id_count = len(str(content).split(self.id_begin)) - 1
        self.is_multi: bool = self.id_count > 1

    @classmethod
    def is_kind(cls, file_abs: str, file_content: bytes) -> bool:
        id_count = len(str(file_content).split(cls.id_begin)) - 1

        if id_count <= 0:
            return False

        return cls.is_valid(file_abs)

    @classmethod
    def is_valid(cls, file_path: str) -> bool:
        out = ss(f"openssl x509 -text -noout -in {file_path}",
                 print_output_on_success=False,
                 print_output_on_error=False,
                 convert_stdout_stderr_to_list=False,
                 exit_on_error=False)

        return out.returncode == 0

    @property
    def valid_dates(self) -> (datetime, datetime):
        if not (self._start_datetime and self._end_datetime):
            out = ss(f"openssl x509 -startdate -noout -in {self.file_abs}",
                     print_output_on_success=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            not_before = out.stdout.strip().split('=')[1]
            self._start_datetime = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")

            out = ss(f"openssl x509 -enddate -noout -in {self.file_abs}",
                     print_output_on_success=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            not_after = out.stdout.strip().split('=')[1]
            self._end_datetime = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

        return self._start_datetime, self._end_datetime

    @property
    def issuer(self) -> str:
        if not self._issuer:
            out = ss(f"openssl x509 -issuer -noout -in {self.file_abs}",
                     print_output_on_success=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            self._issuer = out.stdout.strip().split('issuer= ')[1]

        return self._issuer

    @property
    def subject(self) -> str:
        if not self._subject:
            out = ss(f"openssl x509 -subject -noout -in {self.file_abs}",
                     print_output_on_success=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            self._subject = out.stdout.strip().split('subject= ')[1]

        return self._subject

    @property
    def issuer_hash(self) -> str:
        if not self._issuer_hash:
            out = ss(f"openssl x509 -issuer_hash -noout -in {self.file_abs}",
                     print_output_on_success=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            self._issuer_hash = out.stdout.strip()

        return self._issuer_hash

    @property
    def subject_hash(self) -> str:
        if not self._subject:
            out = ss(f"openssl x509 -subject_hash -noout -in {self.file_abs}",
                     print_output_on_success=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            self._subject_hash = out.stdout.strip()

        return self._subject_hash

    @property
    def common_name(self) -> str:
        return self.subject.split('CN=')[-1].split('/')[0]

    @property
    def subject_alt_names(self) -> list:
        if not self._subject_alt_names:
            out = ss(f"openssl x509 -text -noout -in {self.file_abs} |  grep 'DNS:'",
                     print_output_on_success=False,
                     print_output_on_error=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            sans = out.stdout.strip().split('DNS:')
            sans = [san.strip() for san in sans]
            sans = [san[:-1] for san in sans if san.endswith(',')]

            self._subject_alt_names = sans

        return self._subject_alt_names

    @property
    def modulus_md5(self) -> str:
        if not self._modulus_md5:
            out = ss(f"openssl x509 -modulus -noout -in {self.file_abs} | openssl md5",
                     print_output_on_success=False,
                     print_output_on_error=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            self._modulus_md5 = out.stdout.strip()

        return self._modulus_md5

    def calculate_trusted(self):
        if self.issuer_obj:
            issuer_file = self.issuer_obj.file_abs
        else:
            # Needed for cert bundle
            issuer_file = self.file_abs

        out = ss(f"openssl verify -CAfile {issuer_file} {self.file_abs}",
                 print_output_on_success=False,
                 print_output_on_error=False,
                 convert_stdout_stderr_to_list=False,
                 exit_on_error=False)

        self.is_trusted = out.returncode == 0

    def get_printable_list(self) -> list[str]:
        output = list()
        first_line = self.file_rel

        not_before, not_after = self.valid_dates
        delta = not_after - datetime.now()

        if delta.days <= 0:
            color = "red"
        elif delta.days < 30:
            color = "orange"
        elif delta.days < 90:
            color = "yellow"
        else:
            color = "green"

        first_line += colored(f"  {str(not_before)[:10]} ~ {str(not_after)[:10]} (expires in {delta.days} days)", color)
        if self.is_multi:
            first_line += colored(f"    Chain of {self.id_count} certs", "blue")
        if self.is_trusted:
            first_line += colored(f"    Trusted", "green")
        else:
            first_line += colored(f"    Not trusted", "red")
        output.append(first_line)

        output.append(f"    Common name: {self.common_name}")
        output.append(f"    Subject: {self.subject}")
        if self.subject_alt_names:
            output.append(f"    Subject Alt Names: {self.subject_alt_names}")
        output.append(f"    Issuer: {self.issuer}")
        if self.request:
            output.append(f"    🔏 Request: {self.request.file_rel}")
        if self.private_key:
            output.append(f"    🔑 Signed by: {self.private_key.file_rel}")
        if self.issuer_obj:
            output.append(f"    👑 Issued by: {self.issuer_obj}")
        if self.issuee_objs:
            output.append(f"    👌 Issued: {', '.join(map(str, self.issuee_objs))}")

        return output

    @classmethod
    def print_list(cls, objects: list[X509_PUB]):
        print("🌐 TLS/SSL X509 objects")
        print(" ┃")
        print(" ┣━━ 🔐 Public certificates")

        for obj in objects[:-1]:
            printables: list[str] = obj.get_printable_list()
            print(f" ┃    ├─ {printables[0]}")
            for line in printables[1:]:
                print(f" ┃    │  {line}")
            print(f" ┃    │")

        if objects:
            printables: list[str] = objects[-1].get_printable_list()
            print(f" ┃    └─ {printables[0]}")
            for line in printables[1:]:
                print(f" ┃       {line}")

        print(f" ┃")

    def __str__(self):
        return self.file_rel


class X509_PRV(CryptoObject):
    id_begin = "-----BEGIN RSA PRIVATE KEY-----"
    id_end = "-----END RSA PRIVATE KEY-----"

    def __init__(self, file_abs: str, file_rel: str, content: bytes):
        super().__init__(file_abs, file_rel, self.TYPE_X509_PRV)
        self._modulus_md5: str = None
        self.public_keys: list[X509_PUB] = list()

    @classmethod
    def is_valid(cls, file_path: str) -> bool:
        out = ss(f"openssl rsa -check -noout -in {file_path}",
                 print_output_on_success=False,
                 print_output_on_error=False,
                 convert_stdout_stderr_to_list=False,
                 exit_on_error=False)

        return out.returncode == 0

    @property
    def modulus_md5(self) -> str:
        if not self._modulus_md5:
            out = ss(f"openssl rsa -modulus -noout -in {self.file_abs} | openssl md5",
                     print_output_on_success=False,
                     print_output_on_error=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            self._modulus_md5 = out.stdout.strip()

        return self._modulus_md5

    def get_printable_list(self) -> list[str]:
        output = list()
        output.append(self.file_rel)

        if self.public_keys:
            output.append(f"    🔐 Signed: {', '.join(map(str, self.public_keys))}")

        return output

    @classmethod
    def print_list(cls, objects: list[X509_PRV]):
        print(" ┣━━ 🔑 Private keys")

        for obj in objects[:-1]:
            printables: list[str] = obj.get_printable_list()
            print(f" ┃    ├─ {printables[0]}")
            for line in printables[1:]:
                print(f" ┃    │  {line}")
            print(f" ┃    │")

        if objects:
            printables: list[str] = objects[-1].get_printable_list()
            print(f" ┃    └─ {printables[0]}")
            for line in printables[1:]:
                print(f" ┃       {line}")

        print(" ┃")


class X509_REQ(CryptoObject):
    id_begin = "-----BEGIN CERTIFICATE REQUEST-----"
    id_end = "-----END CERTIFICATE REQUEST-----"

    def __init__(self, file_abs: str, file_rel: str, content: bytes):
        super().__init__(file_abs, file_rel, self.TYPE_X509_REQ)
        self._subject: str = None
        self._subject_alt_names: list = None
        self._modulus_md5: str = None
        self.certificates: list[X509_PUB] = list()

    @classmethod
    def is_valid(cls, file_path: str) -> bool:
        out = ss(f"openssl req -verify -noout -in {file_path}",
                 print_output_on_success=False,
                 print_output_on_error=False,
                 convert_stdout_stderr_to_list=False,
                 exit_on_error=False)

        return out.returncode == 0

    @property
    def subject(self) -> str:
        if not self._subject:
            out = ss(f"openssl req -subject -noout -in {self.file_abs}",
                     print_output_on_success=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            self._subject = out.stdout.strip().split('subject=')[1]

        return self._subject

    @property
    def common_name(self) -> str:
        return self.subject.split('CN=')[-1].split('/')[0]

    @property
    def subject_alt_names(self) -> list:
        if not self._subject_alt_names:
            out = ss(f"openssl req -text -noout -in {self.file_abs} |  grep 'DNS:'",
                     print_output_on_success=False,
                     print_output_on_error=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            sans = out.stdout.strip().split('DNS:')
            sans = [san.strip() for san in sans]
            sans = [san[:-1] for san in sans if san.endswith(',')]

            self._subject_alt_names = sans

        return self._subject_alt_names

    @property
    def modulus_md5(self) -> str:
        if not self._modulus_md5:
            out = ss(f"openssl req -modulus -noout -in {self.file_abs} | openssl md5",
                     print_output_on_success=False,
                     print_output_on_error=False,
                     convert_stdout_stderr_to_list=False,
                     exit_on_error=False)
            self._modulus_md5 = out.stdout.strip()

        return self._modulus_md5

    def get_printable_list(self) -> list[str]:
        output = list()
        output.append(self.file_rel)

        output.append(f"    Common name: {self.common_name}")
        output.append(f"    Subject: {self.subject}")
        if self.subject_alt_names:
            output.append(f"    Subject Alt Names: {self.subject_alt_names}")

        if self.certificates:
            output.append(f"    🔐 Signed and became: {', '.join(map(str, self.certificates))}")
        return output

    @classmethod
    def print_list(cls, objects: list[X509_REQ]):
        print(" ┗━━ 🔏 Certificate Signing Requests")

        for obj in objects[:-1]:
            printables: list[str] = obj.get_printable_list()
            print(f"      ├─ {printables[0]}")
            for line in printables[1:]:
                print(f"      │  {line}")
            print(f"      │")

        if objects:
            printables: list[str] = objects[-1].get_printable_list()
            print(f"      └─ {printables[0]}")
            for line in printables[1:]:
                print(f"         {line}")

        print()


class FileHelper:
    @classmethod
    def get_all_crypto_objects(cls, directories: list[str]) -> dict:
        candidate_files: list[(str, str)] = FileHelper._get_all_candidate_files_in_dirs(list(directories))

        crypto_objects: dict[str: list] = collections.defaultdict(list)

        for file_abs, file_rel in candidate_files:
            crypto_object, kind = CryptoObject.factory(file_abs, file_rel)
            if crypto_object:
                crypto_objects[kind].append(crypto_object)

        cls.match_certs_to_each_other(crypto_objects)

        return crypto_objects

    @classmethod
    def match_certs_to_each_other(cls, crypto_objects: dict[str: CryptoObject]):
        pubs: list[X509_PUB] = crypto_objects.get(CryptoObject.TYPE_X509_PUB, list())
        privs: list[X509_PRV] = crypto_objects.get(CryptoObject.TYPE_X509_PRV, list())
        reqs: list[X509_REQ] = crypto_objects.get(CryptoObject.TYPE_X509_REQ, list())

        for pub in pubs:
            for priv in privs:
                if pub.modulus_md5 == priv.modulus_md5:
                    pub.private_key = priv
                    priv.public_keys.append(pub)

        for pub1 in pubs:
            for pub2 in pubs:
                if pub1.issuer_hash == pub2.subject_hash:
                    pub1.issuer_obj = pub2
                    pub2.issuee_objs.append(pub1)

        for pub in pubs:
            for req in reqs:
                if pub.modulus_md5 == req.modulus_md5:
                    pub.request = req
                    req.certificates.append(pub)

        for pub in pubs:
            pub.calculate_trusted()


    @classmethod
    def _get_all_candidate_files_in_dirs(cls, directories: list[str]) -> list[(str, str)]:
        files = list()

        for directory in directories:
            with os.scandir(os.path.expanduser(directory)) as dir_content:
                for dir_entry in list(dir_content):
                    if dir_entry.is_dir():
                        if cls._is_dir_candidate(dir_entry):
                            directories.append(dir_entry.path)
                    else:
                        if cls._is_file_candidate(dir_entry):
                            files.append((os.path.abspath(dir_entry.path), os.path.relpath(dir_entry.path)))

        return sorted(files, key=lambda x: x[1])

    @classmethod
    def _is_dir_candidate(cls, dir_entry: os.DirEntry) -> bool:
        try:
            if dir_entry.path.endswith(".git"):
                return False

            if dir_entry.path.endswith(".idea"):
                return False
        except:
            return False

        return True

    @classmethod
    def _is_file_candidate(cls, dir_entry: os.DirEntry) -> bool:
        try:
            file_size = dir_entry.stat().st_size
            if file_size < 50 or file_size > 100*1000:
                return False

            file_extension = dir_entry.name.split('.')[-1]
            if file_extension in ['py', 'pyc']:
                return False
        except:
            return False

        return True
