"""Authenticate someone with a challenge and response."""
import secrets
from sha256 import generate_hash

pgp_wordlist = []

with open("pgp_wordlist") as wordsfile:
    for line in wordsfile:
        pgp_wordlist.append(line.split())

def bytes_to_words(hex_bytes: bytearray):
    """Return a list of strings, where each
    string is a word from the PGP word list.
    The argument should be a list of strings,
    where each string is two hex characters."""
    words = []
    for i, value in enumerate(hex_bytes):
        if i % 2 == 0: # even byte
            words.append(pgp_wordlist[value][0].lower())
        else: # odd byte
            words.append(pgp_wordlist[value][1].lower())

    return words

def request_pgp_words(message: str, min_words: int) -> bytearray:
    """Get response as PGP words, convert words to bytearray,
    and make user try again if words aren't in PGP wordlist."""
    found = False
    while not found:
        return_bytes = bytearray()
        print(message)
        response = input().split(" ")
        if len(response) >= min_words: # response must be at least min_words
            for word in response:
                # Check if word is in pgp_wordlist
                found = False
                for index, pgp_word_pair in enumerate(pgp_wordlist):
                    for pgp_word in pgp_word_pair:
                        if word.lower() == pgp_word.lower():
                            found = True
                            # add word's value to bytearray
                            return_bytes.append(index)
                # If word isn't in pgp_wordlist, 
                # stop checking altogether and get a new response
                if found is False:
                    break
    return return_bytes

if __name__ == "__main__":
    choice = ""
    while choice != "1" and choice != "2":
        print("\nI am the..."
              "\n[1] Authenticator"
              "\n[2] Authenticatee")
        choice = input()

    if choice == "1":
        print("\nAuthenticator Mode"
              "\nYou and your partner need to already have "
              "a shared secret password.")

        # Prompt for the password
        password = ""
        while not password:
            print("\nWhat is the shared password?")
            password = input()

        # Generate a challenge nonce
        print("\nShare this challenge with your partner:")
        challenge = secrets.token_hex(2) # a hex string, 2 bytes (4 hex chars)
        # convert each pair of hex characters to an int and store in list
        split = [int(challenge[i:i+2], 16) for i in range(0, len(challenge), 2)]
        challenge_bytes = bytearray(split)
        print(" ".join(bytes_to_words(challenge_bytes)))

        # Prompt for the response
        response_bytes = request_pgp_words("\nWhat is the authenticatee's "
                                           "response?", 3)

        # Calculate correct answer by finding the hash of
        # the password concatenated to the challenge
        correct_bytes = generate_hash(bytearray(password, "ascii")
                                      + challenge_bytes)

        # Validate response
        if response_bytes[:3] == correct_bytes[:3]: # check only first 3 bytes
            print("\nAuthentication successful.")
        else:
            print("\nAuthentication rejected.")

    elif choice == "2":
        print("\nAuthenticatee Mode"
              "\nYou and your partner need to already have "
              "a shared secret password.")

        # Prompt for the password
        password = ""
        while not password:
            print("\nWhat is the shared password?")
            password = input()    

        # Prompt for the challenge
        challenge_bytes = request_pgp_words("\nWhat is the challenge?", 2)

        # Calculate response by finding the hash of
        # the password concatenated to the challenge
        response_bytes = generate_hash(bytearray(password, "ascii")
                                       + challenge_bytes)

        # Send only first 3 bytes as response
        print(" ".join(bytes_to_words(response_bytes[:3])))
