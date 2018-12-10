# Matthew Jones
# COMP 116
# 12 December 2018

import numpy as np
import hashlib
import sys
import random as rn

rn.seed()


# GLOBAL CONSTANTS
# DO NOT CHANGE THESE OR BAD THINGS HAPPEN
PASSWORD_WORDS_FILENAME = 'words.txt'
PASSWORD_STORAGE_FILENAME = 'passes.txt'
SQL_WORDS_FILENAME = 'sqlreserves.txt'
NUM_WORDS = 5
# You can change this one though:
SQL_SEARCH_DEPTH = 10


# Helper function to print without \n
def myprint(a):
    sys.stdout.write(str(a))
    sys.stdout.flush()


# --- FILE READING AND WRITING, WORKING WITH WORDLISTS --------------------------------------------------------------

# Get a single word from a line in the word datafile. Trim non-letter characters ('\n') off the end.
def get_word(datafile):
    word = datafile.readline()
    if word == "":
        return word
    c = word[len(word) - 1]
    while not ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z')):
        word = word[0:len(word) - 1]
        c = word[len(word) - 1]
    return word


# Read the list of words in words.txt
def read_word_file(filename):
    wordfile = open(filename, 'r', encoding='utf8')
    list_of_words = []
    next_word = get_word(wordfile)
    while (next_word != ""):                  # Until no new words exist, get a word. If it has no non-letters, use it
        okay_word = True
        for i in range(len(next_word)):
            c = next_word[i]
            if not ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z')):
                okay_word = False
                break
        if not okay_word:
            next_word = get_word(wordfile)
            continue
        list_of_words.append(next_word)
        next_word = get_word(wordfile)
    wordfile.close()
    return np.array(list_of_words), len(list_of_words)


# This is here, but we won't use it. The word list and sql_reserves list should be constant.
def write_word_file(filename, contents):
    wordfile = open(filename, 'w', encoding='utf8')
    for i in contents:
        wordfile.write(i + '\n')
    wordfile.close()


# Get a single word from a line in the word datafile
def get_cred_pair(datafile):
    cred_pair = datafile.readline()
    if cred_pair == "":
        return None
    while cred_pair[len(cred_pair) - 1] == '\n':
        cred_pair = cred_pair[0:len(cred_pair) - 1]
    credentials = cred_pair.split()
    assert (len(credentials) == 3)                # Should have a username, a salt, and a password hash (sha256)
    return credentials


# read the credentials file
def read_pass_file(filename):
    passfile = open(filename, 'r', encoding='utf8')
    usernames = []
    salts = []
    password_hashes = []
    credentials = get_cred_pair(passfile)
    while credentials != None:                     # Until we run out of lines, parse the line into credentials
        if credentials[0] != 'test':
            usernames.append(credentials[0])
            salts.append(credentials[1])
            password_hashes.append(credentials[2])
        else:                                      # No messing with my test account. Also check that sha256 is working
            usernames.append(credentials[0])
            salts.append(credentials[1])
            password_hashes.append(sha256encrypt_with_salt('MingChowCyberSecurityExpert', credentials[1]))
        credentials = get_cred_pair(passfile)
    passfile.close()
    if len(usernames) == 0:                        # If no accounts were read, add the test case.
        usernames.append('test')
        salts.append(get_random_salt())
        password_hashes.append(sha256encrypt_with_salt('MingChowCyberSecurityExpert', salts[0]))
    return np.array(usernames), np.array(salts), np.array(password_hashes)

# Write the password file. Used at 'exit' and reset.
# Bad things happen if usernames, salts, and password_hashes don't all have the same size
#   (either loss of data or full-blown program crash)
def write_pass_file(usernames, salts, password_hashes):
    passfile = open(PASSWORD_STORAGE_FILENAME, 'w', encoding='utf8')
    for i in range(len(usernames)):
        passfile.write(usernames[i] + ' ' + salts[i] + ' ' + password_hashes[i] + '\n')
    passfile.close()


# Perform a binary search for the query's index in the wordlist. Wordlist must be sorted.
# Returns -1 if query is not in wordlist
# As they are written, word file is sorted and (unmodified) password file is sorted by usernames
def binary_for_index(wordlist, query):
    max_index = len(wordlist) - 1
    min_index = 0
    while (min_index < max_index):
        search_index = int((max_index + min_index) / 2)
        if wordlist[search_index] == query:
            return search_index
        elif wordlist[search_index] < query:
            min_index = search_index + 1
        elif wordlist[search_index] > query:
            max_index = search_index - 1
    if min_index == max_index:
        if wordlist[min_index] == query:
            return min_index
        else:
            return -1
    return -1


# Formatting a wordlist: These two functions are no longer used, only used initially to set up word file
# Works once wordlist is sorted already
def remove_duplicates(wordlist):
    i = 0
    new_wordlist = []
    last_word = "zzzzzzzzz"
    for i in range(len(wordlist)):
        if wordlist[i] != last_word:
            new_wordlist.append(wordlist[i])
            last_word = wordlist[i]
    return np.array(new_wordlist)

# sorts a wordlist (uses selection sort)
def sort_wordlist(wordlist):
    for i in range(len(wordlist) - 1):
        currmin = "temp"
        minidx = -(np.inf)
        for j in range(i,len(wordlist)):
            if minidx < 0 or wordlist[j] < currmin:
                currmin = wordlist[j]
                minidx = j
        temp = wordlist[i]
        wordlist[i] = wordlist[minidx]
        wordlist[minidx] = temp
    remove_duplicates(wordlist)
    return wordlist


# --- CREDENTIAL STUFFS ------------------------------------------------------------------------------------
# returns a random 16-digit salt
def get_random_salt():
    salt = ""
    for i in range(16):         # Total of 16 characters in the salt
        n = rn.randint(48, 109)     # Get random characters. Uses the number of digits and letters of both cases.
        if n > 57 and n < 84:       # If upper-case letter, shift accordingly
            n = n + 7
        elif n > 83:                # If lower-case letter, shift accordingly
            n = n + 13
        salt = salt + chr(n)        # Add the character to the salt.
    return salt


# gets a new randomly generated password
def get_new_password(word_list):
    words = rn.sample(range(len(word_list)), NUM_WORDS)              # Get random list of words for password
    rn.shuffle(words)                                                # Put the words in a random order
    password_str = ''                                                # Build the password string by incrementally adding
    for i in range(NUM_WORDS - 1):                                   # words separated by spaces
        password_str = password_str + word_list[words[i]] + ' '
    password_str = password_str + word_list[words[NUM_WORDS - 1]]
    return password_str


# encrypts a string
# Uses hashlib to encrypt the string, and returns the hex
def sha256encrypt(str):
    encrypter = hashlib.sha256(str.encode())
    return encrypter.hexdigest()


# encrypts a string password 'str' with the salt 'salt'. Wrapper for sha256encrypt
def sha256encrypt_with_salt(str, salt):
    return sha256encrypt(str + salt)

# Rewrite str, converting upper-case letters to lower-case and leaving all other digits as-is.
def lower_case_conversion(str):
    new_str = ''
    for i in range(len(str)):
        if (str[i] >= 'A' and str[i] <= 'Z'):
            new_str = new_str + chr(ord(str[i]) - ord('A') + ord('a'))
        else:
            new_str = new_str + str[i]
    return new_str


# Puts password in the authentication format and then encrypts it
# If the password is not valid within the wordlist provided or the number of words required,
#   will check the first n (or fewer, if fewer exist) words for SQL reserved words, and returns None on encryption
#   n is equal to SQL_SEARCH_DEPTH
# Returns:
#   - encryption   : The encryption, if the password is valid. None otherwise
#   - sql_keywords : SQL keywords in the first n words if password is invalid. Empty list if none are found or
#                      password encryption is successful. Should only be non-empty if encryption is None.
def encrypt_password(password, salt, word_list, sql_words):
    valid_password = True
    pw = lower_case_conversion(password)
    pw_word_list = pw.split(' ')
    if len(pw_word_list) != NUM_WORDS:                         # Password is invalid if number of words is incorrect
        valid_password = False
    if valid_password:                                         # Password is invalid if invalid word is found
        for i in range(NUM_WORDS):
            idx = binary_for_index(word_list, pw_word_list[i])
            if idx == -1:
                valid_password = False
                break
    if valid_password:                                         # If valid form,
        password_to_encrypt = ''                               # reformat: (no spaces, words are capitalized and then
        for i in range(NUM_WORDS):                             # joined, then salt is added at encryption)
            password_to_encrypt = password_to_encrypt + chr(ord(pw_word_list[i][0]) + ord('A') - ord('a'))
            password_to_encrypt = password_to_encrypt + pw_word_list[i][1:len(pw_word_list[i])]
        return sha256encrypt_with_salt(password_to_encrypt, salt), []
    else:                                                      # If not valid form, look in first SQL_SEARCH_DEPTH
        sql_keywords = []                                      # words for SQL keywords.
        for i in range(min(len(pw_word_list), SQL_SEARCH_DEPTH)):
            idx = binary_for_index(sql_words, pw_word_list[i])
            if idx != -1:
                sql_keywords.append(pw_word_list[i])
        return None, sql_keywords

# --- MAIN BODY ---------------------------------------------------------------------------------------------------
# All functions which take usernames/salts/password_hashes arguments assumes these arrays are the same sizes, and
# can have major issues if this is not the case.


# Add a username, give a random password
def add_process(usernames, salts, password_hashes, password_words, sql_words):
    command_print("Usernames should be only letters (capital and lower case) and underscores.")
    command_print("Also, the first character should not be an underscore. No symbols or spaces!")
    command_print("Input username")
    new_username = input("  : ")
    # First, check empty case
    if len(new_username) == 0:
        error_to_user(["No characters input in username.", "Aborting the 'add user' process."])
        return usernames, salts, password_hashes
    # Then, check format: starts with a letter, only contains letters and underscores
    if not ((new_username[0] <= 'z' and new_username[0] >= 'a') or (new_username[0] <= 'Z' and new_username[0] >= 'A')):
        error_to_user(["Invalid character at the start of username.", "Aborting the 'add user' process."])
        return usernames, salts, password_hashes
    for i in range(len(new_username)):
        c = new_username[i]
        if not ((c <= 'z' and c >= 'a') or (c <= 'Z' and c >= 'A') or (c == '_')):
            error_to_user(["Invalid character '{:s}' found in username.".format(c), "Aborting the 'add user' process"])
            return usernames, salts, password_hashes
    # Check if username already exists
    already_exists = binary_for_index(usernames, new_username)
    if already_exists != -1:
        error_to_user(["User with that username already exists.", "Aborting the 'add user' process."])
        return usernames, salts, password_hashes
    # At this point, we have a username of valid format.
    # Create the password
    command_print("Creating user with username '{:s}'".format(new_username))
    new_salt = get_random_salt()
    new_password = get_new_password(password_words)
    new_hash, sql_list = encrypt_password(new_password, new_salt, password_words, sql_words)
    assert (new_hash is not None)
    new_username_list = []
    new_salts_list = []
    new_password_hashes_list = []
    inserted = False
    # Insert username into sorted list
    for i in range(len(usernames)):
        if not inserted and usernames[i] > new_username:
            new_username_list.append(new_username)
            new_salts_list.append(new_salt)
            new_password_hashes_list.append(new_hash)
            inserted = True
        new_username_list.append(usernames[i])
        new_salts_list.append(salts[i])
        new_password_hashes_list.append(password_hashes[i])
    # Print and return
    command_print("New user '{:s}' created.".format(new_username))
    command_print("Password is '{:s}'".format(new_password))
    command_print(" Remember that passwords are NOT case-sensitive!")
    return np.array(new_username_list), np.array(new_salts_list), np.array(new_password_hashes_list)


# Remove a user from the system.
# as_admin is True iff operating as admin
def remove_process(usernames, salts, password_hashes, as_admin, word_list, sql_words):
    command_print("Input username to remove: ")
    key_username = input("  : ")
    if key_username == 'test':
        command_print("System Error: Please don't mess with 'test'! To remove a user, add a new user first.")
        return usernames, salts, password_hashes
    # First, check empty case
    if len(key_username) < 1:
        if as_admin:
            error_to_admin(["Empty username entered.", "Aborting the 'remove user' process."])
        else:
            error_to_user(["Empty username entered.", "Aborting the 'remove user' process."])
        return usernames, salts, password_hashes
    valid = True
    # Then, check format: starts with a letter, only contains letters and underscores
    c = key_username[0]
    if not ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z')):
        if as_admin:
            error_to_admin(["Invalid format, must start with a letter.", "Aborting the 'remove user' process."])
            return usernames, salts, password_hashes
        valid = False
    for i in range(1, len(key_username)):
        c = key_username[i]
        if not ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c == '_')):
            if as_admin:
                error_to_admin(["Invalid format, all characters must be letters or underscores.",
                                "Aborting the 'remove user' process."])
                return usernames, salts, password_hashes
            valid = False
    # Check if username exists
    if valid:
        idx = binary_for_index(usernames, key_username)
        if idx == -1:
            if as_admin:
                error_to_admin(["User with username '{:s}' does not exist.".format(key_username),
                                "Aborting the 'remove user' process."])
                return usernames, salts, password_hashes
            valid = False
    if not as_admin:
        # Now, get password (even if username is invalid, since non-admin)
        command_print("Input password for user: ")
        key_password = input("  : ")
        if valid:
            encryption, sql_detect = encrypt_password(key_password, salts[idx], word_list, sql_words)
        else:
            encryption, sql_detect = encrypt_password(key_password, "", word_list, sql_words)
        if encryption is None:
            valid = False
        if valid and encryption == password_hashes[idx]:
            # If valid username and password, remove user and return
            command_print("Username and password match. Deleting user '{:s}'...".format(key_username))
            new_password_hashes = password_hashes[usernames != key_username]
            new_salts = salts[usernames != key_username]
            new_usernames = usernames[usernames != key_username]
            command_print("Deleted.")
            return new_usernames, new_salts, new_password_hashes
        else:
            # Otherwise, failure and possibly report sql to admin
            error_to_user(["Invalid username and/or password.", "Aborting the 'remove user' process."])
            if len(sql_detect) != 0:
                sqlstr = ''
                for i in range(0, len(sql_detect) - 1, 1):
                    sqlstr = sqlstr + sql_detect[i] + ', '
                sqlstr = sqlstr + sql_detect[len(sql_detect) - 1]
                error_to_admin(["Found possible SQL injection in password input.",
                                "SQL keywords found were [{:s}]".format(sqlstr),
                                "In process to delete user."])
            return usernames, salts, password_hashes
    if as_admin:
        # If valid username, remove user and return
        command_print("Deleting user '{:s}'...".format(key_username))
        new_password_hashes = password_hashes[usernames != key_username]
        new_salts = salts[usernames != key_username]
        new_usernames = usernames[usernames != key_username]
        command_print("Deleted.")
        return new_usernames, new_salts, new_password_hashes


# Change a password, by getting a new random password.
# as_admin is True iff operating as admin
def change_password_process(usernames, salts, password_hashes, as_admin, word_list, sql_words):
    command_print("Input username to get a new password for: ")
    key_username = input("  : ")
    if key_username == 'test':
        command_print("System Error: Please don't mess with 'test'! To change a password, add a new user first.")
        return usernames, salts, password_hashes
    # First, check empty case
    if len(key_username) < 1:
        if as_admin:
            error_to_admin(["Empty username entered.", "Aborting the 'change user' process."])
        else:
            error_to_user(["Empty username entered.", "Aborting the 'change user' process."])
        return usernames, salts, password_hashes
    valid = True
    # Then, check format: starts with a letter, only contains letters and underscores
    c = key_username[0]
    if not ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z')):
        if as_admin:
            error_to_admin(["Invalid format, must start with a letter.", "Aborting the 'change user' process."])
            return usernames, salts, password_hashes
        valid = False
    for i in range(1, len(key_username)):
        c = key_username[i]
        if not ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c == '_')):
            if as_admin:
                error_to_admin(["Invalid format, all characters must be letters or underscores.",
                                "Aborting the 'change user' process."])
                return usernames, salts, password_hashes
            valid = False
    # Check if username exists
    if valid:
        idx = binary_for_index(usernames, key_username)
        if idx == -1:
            if as_admin:
                error_to_admin(["User with username '{:s}' does not exist.".format(key_username),
                                "Aborting the 'change user' process."])
                return usernames, salts, password_hashes
            valid = False
    if not as_admin:
        # Now, get password (even if username is invalid, since non-admin)
        command_print("Input password for user: ")
        key_password = input("  : ")
        if valid:
            encryption, sql_detect = encrypt_password(key_password, salts[idx], word_list, sql_words)
        else:
            encryption, sql_detect = encrypt_password(key_password, "", word_list, sql_words)
        if encryption is None:
            valid = False
        if valid and encryption == password_hashes[idx]:
            # If valid username and password, change password and return
            command_print("Username and password match. Getting new password for user '{:s}'...".format(key_username))
            new_password = get_new_password(word_list)
            new_salt = get_random_salt()
            new_password_hash, sql_detect = encrypt_password(new_password, new_salt, word_list, sql_words)
            salts[idx] = new_salt
            password_hashes[idx] = new_password_hash
            command_print("New password for user '{:s}' is '{:s}'".format(key_username, new_password))
            command_print(" Remember that passwords are NOT case-sensitive!")
            return usernames, salts, password_hashes
        else:
            # Otherwise, report error and possibly report sql to admin
            error_to_user(["Invalid username and/or password.", "Aborting the 'change user' process."])
            if len(sql_detect) != 0:
                sqlstr = ''
                for i in range(0, len(sql_detect) - 1, 1):
                    sqlstr = sqlstr + sql_detect[i] + ', '
                sqlstr = sqlstr + sql_detect[len(sql_detect) - 1]
                error_to_admin(["Found possible SQL injection in password input.",
                                "SQL keywords found were [{:s}]".format(sqlstr),
                                "In process to change password."])
            return usernames, salts, password_hashes
    if as_admin:
        # If valid username, change password and return
        command_print("Getting new password for user '{:s}'...".format(key_username))
        new_password = get_new_password(word_list)
        new_salt = get_random_salt()
        new_password_hash, sql_detect = encrypt_password(new_password, new_salt, word_list, sql_words)
        salts[idx] = new_salt
        password_hashes[idx] = new_password_hash
        command_print("New password for user '{:s}' is '{:s}'".format(key_username, new_password))
        command_print(" Remember that passwords are NOT case-sensitive!")
        return usernames, salts, password_hashes


# Verify credentials. No actual login happens, just checking of credentials.
def login_process(usernames, salts, password_hashes, word_list, sql_words):
    command_print("Input username: ")
    key_username = input("  : ")
    # First, check empty case
    if len(key_username) < 1:
        error_to_user(["Empty username entered.", "Aborting the 'login' process."])
        return
    valid = True
    # Then, check format: starts with a letter, only contains letters and underscores
    c = key_username[0]
    if not ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z')):
        valid = False
    for i in range(1, len(key_username)):
        c = key_username[i]
        if not ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c == '_')):
            valid = False
    # Check if username exists
    if valid:
        idx = binary_for_index(usernames, key_username)
        if idx == -1:
            valid = False
    # Now, get password (even if username is invalid)
    command_print("Input password for user: ")
    key_password = input("  : ")
    if valid:
        encryption, sql_detect = encrypt_password(key_password, salts[idx], word_list, sql_words)
    else:
        encryption, sql_detect = encrypt_password(key_password, "", word_list, sql_words)
    if encryption is None:
        valid = False
    if valid and encryption == password_hashes[idx]:
        # If valid username and password, report success (no actual login) and return
        command_print("Username and password match. Logged in as '{:s}'.".format(key_username))
        return
    else:
        # Otherwise, report error and possibly report sql to admin
        error_to_user(["Invalid username and/or password.", "Aborting the 'login' process."])
        if len(sql_detect) != 0:
            sqlstr = ''
            for i in range(0, len(sql_detect) - 1, 1):
                sqlstr = sqlstr + sql_detect[i] + ', '
            sqlstr = sqlstr + sql_detect[len(sql_detect) - 1]
            error_to_admin(["Found possible SQL injection in password input.",
                            "SQL keywords found were [{:s}]".format(sqlstr),
                            "In process to log in."])
        return


# Special print, formatted
def command_print(to_print):
    myprint("   ")
    print(to_print)


# Output of an error reported to user.
def error_to_user(lines):
    assert(len(lines) > 0)
    print("Error message to user: ")
    for i in range(len(lines)):
        myprint("     ")
        print(lines[i])


# Output of an error reported to admin.
def error_to_admin(lines):
    assert(len(lines) > 0)
    print("Error message to admin: ")
    for i in range(len(lines)):
        myprint("     ")
        print(lines[i])


# Prints help output, giving commands
def print_help():
    print("List of commands for the system:")
    print("login    : Opens a guided system for logging in (authentication process, no actual login)")
    print("add      : Opens a guided system for adding a new user. Prompts username, and gives password.")
    print("remove_u : Opens a guided system for removing a user, as that user. Requires authentication.")
    print("remove_a : Opens a guided system for removing a user, as an admin. Does not require authentication.")
    print("change_u : Opens a guided system to get a new password for a user, as that user. ")
    print("           Requires authentication.")
    print("change_a : Opens a guided system to get a new password for a user, as an admin.")
    print("           Does not require authentication.")
    print("exit     : Saves credentials for users on system. Exiting without this method will cause")
    print("list     : Lists all usernames on the system.")
    print("           anything done in this session to be lost, reverting to before the session began.")
    print("help     : Show this message again.")


# reset the credentials data to 'initial.txt'
def reset_function():
    initial_state = open('initial.txt', 'r')
    comment_line = initial_state.readline()
    initial_data = initial_state.read()
    initial_state.close()
    rewrite_initial = open('initial.txt', 'w')
    rewrite_initial.write(initial_data)
    rewrite_initial.close()
    initusers, initsalts, inithashes = read_pass_file('initial.txt')
    write_pass_file(initusers, initsalts, inithashes)
    restore_initial = open('initial.txt', 'w')
    restore_initial.write(comment_line + initial_data)
    restore_initial.close()
    return


# Main function. Initially print welcome message and help output, then iteratively get/perform commands.
# Also has a reset functionality to restore an initial state before edits, but that is a command line parameter
def main():
    if len(sys.argv) == 2:
        if sys.argv[1] == 'reset':
            reset_function()
            print("Reset credentials.")
            return
    print("Welcome to my (mock) random-word-password generating system!")
    print("This system is designed to simulate how such a password system could behave in practice.")
    print("Obviously this is not a complete password system that could be used as is in the real world,")
    print(" but it should serve as proof-of-concept. In it, you are able to add (and remove) accounts.")
    print("Note that the login system does not actually log you in or out, since there isn't anything")
    print(" to actually gain authorized access to, but it will tell you errors, both as a system administrator")
    print(" would see them, and as a user would see them. In the case of the remove and change instructions,")
    print(" the instruction behaves differently on whether you are calling as an admin or a non-admin. In")
    print(" this case, this mock program allows you to be either.")
    print("The system will always start with at least one user, 'test', whose password is")
    print(" 'ming chow cyber security expert'.")
    print("For more information on files and brief code information, see 'README.txt'")
    print("Have fun!")
    print("----------------------------------------------------------------------------------------------------------")
    word_list, num_words = read_word_file(PASSWORD_WORDS_FILENAME)
    user_list, salts, password_hashes = read_pass_file(PASSWORD_STORAGE_FILENAME)
    sql_word_list, num_words = read_word_file(SQL_WORDS_FILENAME)
    condition = True
    print("\n>> help")
    print_help()
    while(condition):                              # Until we exit, get commands and perform them
        next_instruction = input("\n>> ")
        if next_instruction == 'login':
            login_process(user_list, salts, password_hashes, word_list, sql_word_list)
        elif next_instruction == 'add':
            user_list, salts, password_hashes = add_process(user_list, salts, password_hashes, word_list, sql_word_list)
        elif next_instruction == 'remove_u':
            user_list, salts, password_hashes = remove_process(user_list, salts, password_hashes, False, word_list,
                                                               sql_word_list)
        elif next_instruction == 'remove_a':
            user_list, salts, password_hashes = remove_process(user_list, salts, password_hashes, True, word_list,
                                                               sql_word_list)
        elif next_instruction == 'change_u':
            user_list, salts, password_hashes = change_password_process(user_list, salts, password_hashes, False,
                                                                        word_list, sql_word_list)
        elif next_instruction == 'change_a':
            user_list, salts, password_hashes = change_password_process(user_list, salts, password_hashes, True,
                                                                        word_list, sql_word_list)
        elif next_instruction == 'list':
            for i in range(len(user_list)):
                command_print(" - {:s}".format(user_list[i]))
        elif next_instruction == 'help':
            print_help()
        elif next_instruction == 'exit':
            print("Saving...")
            write_pass_file(user_list, salts, password_hashes)
            condition = False
            print("Thanks, and goodbye!")
        else:
            print("   System Error: Invalid command '{:s}', use 'help' to view commands.".format(next_instruction))

# Now, the fancy stuff:
main()