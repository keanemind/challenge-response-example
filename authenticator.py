"""Authenticate someone with a challenge and response."""
import secrets
from sha256 import generate_hash

PGP_WORDLIST = [
    ["aardvark", "adroitness"],
    ["absurd", "adviser"],
    ["accrue", "aftermath"],
    ["acme", "aggregate"],
    ["adrift", "alkali"],
    ["adult", "almighty"],
    ["afflict", "amulet"],
    ["ahead", "amusement"],
    ["aimless", "antenna"],
    ["Algol", "applicant"],
    ["allow", "Apollo"],
    ["alone", "armistice"],
    ["ammo", "article"],
    ["ancient", "asteroid"],
    ["apple", "Atlantic"],
    ["artist", "atmosphere"],
    ["assume", "autopsy"],
    ["Athens", "Babylon"],
    ["atlas", "backwater"],
    ["Aztec", "barbecue"],
    ["baboon", "belowground"],
    ["backfield", "bifocals"],
    ["backward", "bodyguard"],
    ["banjo", "bookseller"],
    ["beaming", "borderline"],
    ["bedlamp", "bottomless"],
    ["beehive", "Bradbury"],
    ["beeswax", "bravado"],
    ["befriend", "Brazilian"],
    ["Belfast", "breakaway"],
    ["berserk", "Burlington"],
    ["billiard", "businessman"],
    ["bison", "butterfat"],
    ["blackjack", "Camelot"],
    ["blockade", "candidate"],
    ["blowtorch", "cannonball"],
    ["bluebird", "Capricorn"],
    ["bombast", "caravan"],
    ["bookshelf", "caretaker"],
    ["brackish", "celebrate"],
    ["breadline", "cellulose"],
    ["breakup", "certify"],
    ["brickyard", "chambermaid"],
    ["briefcase", "Cherokee"],
    ["Burbank", "Chicago"],
    ["button", "clergyman"],
    ["buzzard", "coherence"],
    ["cement", "combustion"],
    ["chairlift", "commando"],
    ["chatter", "company"],
    ["checkup", "component"],
    ["chisel", "concurrent"],
    ["choking", "confidence"],
    ["chopper", "conformist"],
    ["Christmas", "congregate"],
    ["clamshell", "consensus"],
    ["classic", "consulting"],
    ["classroom", "corporate"],
    ["cleanup", "corrosion"],
    ["clockwork", "councilman"],
    ["cobra", "crossover"],
    ["commence", "crucifix"],
    ["concert", "cumbersome"],
    ["cowbell", "customer"],
    ["crackdown", "Dakota"],
    ["cranky", "decadence"],
    ["crowfoot", "December"],
    ["crucial", "decimal"],
    ["crumpled", "designing"],
    ["crusade", "detector"],
    ["cubic", "detergent"],
    ["dashboard", "determine"],
    ["deadbolt", "dictator"],
    ["deckhand", "dinosaur"],
    ["dogsled", "direction"],
    ["dragnet", "disable"],
    ["drainage", "disbelief"],
    ["dreadful", "disruptive"],
    ["drifter", "distortion"],
    ["dropper", "document"],
    ["drumbeat", "embezzle"],
    ["drunken", "enchanting"],
    ["Dupont", "enrollment"],
    ["dwelling", "enterprise"],
    ["eating", "equation"],
    ["edict", "equipment"],
    ["egghead", "escapade"],
    ["eightball", "Eskimo"],
    ["endorse", "everyday"],
    ["endow", "examine"],
    ["enlist", "existence"],
    ["erase", "exodus"],
    ["escape", "fascinate"],
    ["exceed", "filament"],
    ["eyeglass", "finicky"],
    ["eyetooth", "forever"],
    ["facial", "fortitude"],
    ["fallout", "frequency"],
    ["flagpole", "gadgetry"],
    ["flatfoot", "Galveston"],
    ["flytrap", "getaway"],
    ["fracture", "glossary"],
    ["framework", "gossamer"],
    ["freedom", "graduate"],
    ["frighten", "gravity"],
    ["gazelle", "guitarist"],
    ["Geiger", "hamburger"],
    ["glitter", "Hamilton"],
    ["glucose", "handiwork"],
    ["goggles", "hazardous"],
    ["goldfish", "headwaters"],
    ["gremlin", "hemisphere"],
    ["guidance", "hesitate"],
    ["hamlet", "hideaway"],
    ["highchair", "holiness"],
    ["hockey", "hurricane"],
    ["indoors", "hydraulic"],
    ["indulge", "impartial"],
    ["inverse", "impetus"],
    ["involve", "inception"],
    ["island", "indigo"],
    ["jawbone", "inertia"],
    ["keyboard", "infancy"],
    ["kickoff", "inferno"],
    ["kiwi", "informant"],
    ["klaxon", "insincere"],
    ["locale", "insurgent"],
    ["lockup", "integrate"],
    ["merit", "intention"],
    ["minnow", "inventive"],
    ["miser", "Istanbul"],
    ["Mohawk", "Jamaica"],
    ["mural", "Jupiter"],
    ["music", "leprosy"],
    ["necklace", "letterhead"],
    ["Neptune", "liberty"],
    ["newborn", "maritime"],
    ["nightbird", "matchmaker"],
    ["Oakland", "maverick"],
    ["obtuse", "Medusa"],
    ["offload", "megaton"],
    ["optic", "microscope"],
    ["orca", "microwave"],
    ["payday", "midsummer"],
    ["peachy", "millionaire"],
    ["pheasant", "miracle"],
    ["physique", "misnomer"],
    ["playhouse", "molasses"],
    ["Pluto", "molecule"],
    ["preclude", "Montana"],
    ["prefer", "monument"],
    ["preshrunk", "mosquito"],
    ["printer", "narrative"],
    ["prowler", "nebula"],
    ["pupil", "newsletter"],
    ["puppy", "Norwegian"],
    ["python", "October"],
    ["quadrant", "Ohio"],
    ["quiver", "onlooker"],
    ["quota", "opulent"],
    ["ragtime", "Orlando"],
    ["ratchet", "outfielder"],
    ["rebirth", "Pacific"],
    ["reform", "pandemic"],
    ["regain", "Pandora"],
    ["reindeer", "paperweight"],
    ["rematch", "paragon"],
    ["repay", "paragraph"],
    ["retouch", "paramount"],
    ["revenge", "passenger"],
    ["reward", "pedigree"],
    ["rhythm", "Pegasus"],
    ["ribcage", "penetrate"],
    ["ringbolt", "perceptive"],
    ["robust", "performance"],
    ["rocker", "pharmacy"],
    ["ruffled", "phonetic"],
    ["sailboat", "photograph"],
    ["sawdust", "pioneer"],
    ["scallion", "pocketful"],
    ["scenic", "politeness"],
    ["scorecard", "positive"],
    ["Scotland", "potato"],
    ["seabird", "processor"],
    ["select", "provincial"],
    ["sentence", "proximate"],
    ["shadow", "puberty"],
    ["shamrock", "publisher"],
    ["showgirl", "pyramid"],
    ["skullcap", "quantity"],
    ["skydive", "racketeer"],
    ["slingshot", "rebellion"],
    ["slowdown", "recipe"],
    ["snapline", "recover"],
    ["snapshot", "repellent"],
    ["snowcap", "replica"],
    ["snowslide", "reproduce"],
    ["solo", "resistor"],
    ["southward", "responsive"],
    ["soybean", "retraction"],
    ["spaniel", "retrieval"],
    ["spearhead", "retrospect"],
    ["spellbind", "revenue"],
    ["spheroid", "revival"],
    ["spigot", "revolver"],
    ["spindle", "sandalwood"],
    ["spyglass", "sardonic"],
    ["stagehand", "Saturday"],
    ["stagnate", "savagery"],
    ["stairway", "scavenger"],
    ["standard", "sensation"],
    ["stapler", "sociable"],
    ["steamship", "souvenir"],
    ["sterling", "specialist"],
    ["stockman", "speculate"],
    ["stopwatch", "stethoscope"],
    ["stormy", "stupendous"],
    ["sugar", "supportive"],
    ["surmount", "surrender"],
    ["suspense", "suspicious"],
    ["sweatband", "sympathy"],
    ["swelter", "tambourine"],
    ["tactics", "telephone"],
    ["talon", "therapist"],
    ["tapeworm", "tobacco"],
    ["tempest", "tolerance"],
    ["tiger", "tomorrow"],
    ["tissue", "torpedo"],
    ["tonic", "tradition"],
    ["topmost", "travesty"],
    ["tracker", "trombonist"],
    ["transit", "truncated"],
    ["trauma", "typewriter"],
    ["treadmill", "ultimate"],
    ["Trojan", "undaunted"],
    ["trouble", "underfoot"],
    ["tumor", "unicorn"],
    ["tunnel", "unify"],
    ["tycoon", "universe"],
    ["uncut", "unravel"],
    ["unearth", "upcoming"],
    ["unwind", "vacancy"],
    ["uproot", "vagabond"],
    ["upset", "vertigo"],
    ["upshot", "Virginia"],
    ["vapor", "visitor"],
    ["village", "vocalist"],
    ["virus", "voyager"],
    ["Vulcan", "warranty"],
    ["waffle", "Waterloo"],
    ["wallet", "whimsical"],
    ["watchword", "Wichita"],
    ["wayside", "Wilmington"],
    ["willow", "Wyoming"],
    ["woodlark", "yesteryear"],
    ["Zulu", "Yucatan"]
]

def bytes_to_words(hex_bytes: bytearray):
    """Return a list of strings, where each
    string is a word from the PGP word list.
    The argument should be a list of strings,
    where each string is two hex characters."""
    words = []
    for i, value in enumerate(hex_bytes):
        if i % 2 == 0: # even byte
            words.append(PGP_WORDLIST[value][0].lower())
        else: # odd byte
            words.append(PGP_WORDLIST[value][1].lower())

    return words

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

        password = ""
        while not password:
            print("\nWhat is the shared password?")
            password = input()

        print("\nShare this challenge with your partner:")
        challenge = secrets.token_hex(2) # a hex string, 2 bytes (4 hex chars)
        # convert each pair of hex characters to an int and store in list
        split = [int(challenge[i:i+2], 16) for i in range(0, len(challenge), 2)]
        challenge_bytes = bytearray(split)
        print(" ".join(bytes_to_words(challenge_bytes)))

        # Get response as PGP words, convert words to bytearray,
        # and make user try again if words aren't in PGP wordlist
        found = False
        while not found:
            response_bytes = bytearray()
            print("\nWhat is the authenticatee's response?")
            response = input().split(" ")
            if len(response) >= 3: # response must be at least 3 bytes 
                for word in response:
                    # Check if word is in PGP_WORDLIST
                    found = False
                    for index, pgp_word_pair in enumerate(PGP_WORDLIST):
                        for pgp_word in pgp_word_pair:
                            if word.lower() == pgp_word.lower():
                                found = True
                                # add word's value to bytearray
                                response_bytes.append(index)
                    # If word isn't in PGP_WORDLIST, 
                    # stop checking altogether and get a new response
                    if found is False:
                        break

        # Calculate correct answer by calculating hash of
        # the password concatenated to the challenge
        correct_bytes = generate_hash(bytearray(password, "ascii")
                                      + challenge_bytes)
        if response_bytes[:3] == correct_bytes[:3]: # check only first 3 bytes
            print("\nAuthentication successful.")
        else:
            print("\nAuthentication rejected.")
