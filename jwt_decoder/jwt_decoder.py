# import modules
from argparse import ArgumentParser
from json import loads as jloads
from base64 import urlsafe_b64decode as base64decode


def get_arguments():
    """
    Description: Collects JWT token as input
    """

    parser = ArgumentParser(
        description="Takes a JWT token and decodes it."
    )

    # defining one of the allowed arguments
    parser.add_argument(
        "-jwt",
        type=str,
        help="Provide the encoded JWT token",
        required=True
    )

    # save all the arguments
    args = parser.parse_args()

    # return value of args
    return args


def decode_jwt(jwt_token):
    """
    Description: Decode the JWT token.
    """

    # tries to split JWT into header, payload, signature
    try:
        header, payload, signature = jwt_token.split(".")
    except ValueError:
        raise ValueError("Invalid format for JWT")

    # try to decode each section of the JWT
    def decode_section(section):

        # this re-adds the padding removed from JWTs https://datatracker.ietf.org/doc/html/rfc7515#section-2:~:text=JWS)%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20May%202015-,Base64url%20Encoding,-Base64%20encoding%20using
        padding = len(section) % 4
        if padding:
            section += '=' * (4 - padding)

        # base64 decode each section and parse as JSON
        try:
            decoded = base64decode(section)
            return jloads(decoded)
        except:
            return "Error: cannot decode JWT"

    # saves the new decoded info into each section
    decoded_header = decode_section(header)
    decoded_payload = decode_section(payload)
    decoded_signature = signature

    # return the results of the decoded sections
    return {
        'header': decoded_header,
        'payload': decoded_payload,
        'signature': decoded_signature
    }


def main():
    """
    Description: Main function, executes script.
    """

    args = get_arguments()

    decoded_token_value = decode_jwt(jwt_token=args.jwt)

    # prints the sections out in a nicer format
    print("\n---Header---")
    for key, value in decoded_token_value['header'].items():
        print(f"{key}: {value}")

    print("\n---Payload---")
    for key, value in decoded_token_value['payload'].items():
        print(f"{key}: {value}")

    print("\n---Signature---")
    print(decoded_token_value['signature'])


if __name__ == "__main__":
    main()
