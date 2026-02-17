#!/usr/bin/env python3
import argparse
import os
import sys

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.bio import CaptureError, FPBioEnrollment
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CtapHidDevice


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enroll a fingerprint and verify it via makeCredential/getAssertion."
    )
    parser.add_argument("--pin", required=True, help="Authenticator PIN")
    parser.add_argument("--rp-id", default="example.com", help="Relying party ID")
    parser.add_argument("--rp-name", default="Bio Test RP", help="Relying party name")
    parser.add_argument("--user-name", default="bio-user", help="User name")
    parser.add_argument("--user-display", default="Bio User", help="User display name")
    parser.add_argument("--enroll-timeout-ms", type=int, default=20000, help="Enrollment sample timeout")
    parser.add_argument("--friendly-name", default="finger-1", help="Template friendly name")
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Do not remove existing enrolled fingerprints before enrolling",
    )
    return parser.parse_args()


def first_device():
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        raise RuntimeError("No CTAP HID authenticator found")
    return dev


def main():
    args = parse_args()

    dev = first_device()
    ctap = Ctap2(dev)
    info = ctap.info

    if not info.options.get("bioEnroll", False):
        raise RuntimeError("Authenticator does not report bioEnroll support in getInfo")

    pin_client = ClientPin(ctap)
    pin_protocol = PinProtocolV2()

    print("[1/4] Getting BioEnroll permission token")
    be_token = pin_client.get_pin_token(
        args.pin,
        permissions=ClientPin.PERMISSION.BIO_ENROLL,
    )
    bio = FPBioEnrollment(ctap, pin_protocol, be_token)

    print("[2/4] Enrolling fingerprint")
    existing = bio.enumerate_enrollments()
    if existing and not args.keep_existing:
        print(f"Found {len(existing)} existing template(s), removing them first")
        for template_id in existing.keys():
            bio.remove_enrollment(template_id)

    ctx = bio.enroll(timeout=args.enroll_timeout_ms)
    template_id = None
    while template_id is None:
        try:
            template_id = ctx.capture()
        except CaptureError as exc:
            print(f"Capture feedback: {exc}")
            continue
        if template_id is None:
            print(f"Capture OK, remaining samples: {ctx.remaining}")

    if args.friendly_name:
        bio.set_name(template_id, args.friendly_name)
    print(f"Enrollment complete, template id: {template_id.hex()}")

    print("[3/4] Creating credential (UP check should accept enrolled finger)")
    mc_ga_token = pin_client.get_pin_token(
        args.pin,
        permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION,
        permissions_rpid=args.rp_id,
    )
    challenge_mc = os.urandom(32)
    pin_uv_param_mc = pin_protocol.authenticate(mc_ga_token, challenge_mc)
    attestation = ctap.make_credential(
        client_data_hash=challenge_mc,
        rp={"id": args.rp_id, "name": args.rp_name},
        user={
            "id": os.urandom(16),
            "name": args.user_name,
            "displayName": args.user_display,
        },
        key_params=info.algorithms,
        options={"rk": True},
        pin_uv_param=pin_uv_param_mc,
        pin_uv_protocol=pin_protocol.VERSION,
    )
    cred_id = attestation.auth_data.credential_data.credential_id

    print("[4/4] Getting assertion (verification path)")
    challenge_ga = os.urandom(32)
    pin_uv_param_ga = pin_protocol.authenticate(mc_ga_token, challenge_ga)
    ctap.get_assertion(
        rp_id=args.rp_id,
        client_data_hash=challenge_ga,
        allow_list=[{"type": "public-key", "id": cred_id}],
        pin_uv_param=pin_uv_param_ga,
        pin_uv_protocol=pin_protocol.VERSION,
    )

    print("Success: enroll and verification flow completed.")


if __name__ == "__main__":
    try:
        main()
    except CtapError as err:
        print(f"CTAP error: {err}", file=sys.stderr)
        sys.exit(1)
    except Exception as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
