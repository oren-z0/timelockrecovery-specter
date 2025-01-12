import json
import logging

from cryptoadvance.specter.services.service import Service, devstatus_alpha
from cryptoadvance.specter.specter_error import handle_exception
from flask import current_app as app, flash
from flask_babel import lazy_gettext as _
from cryptoadvance.specter.wallet import Wallet
from embit.psbt import PSBT
from ._version import version

logger = logging.getLogger(__name__)

class TimelockrecoveryService(Service):
    id = "timelockrecovery"
    version = version
    name = "Timelock Recovery"
    icon = "timelockrecovery/img/logo160.png"
    logo = "timelockrecovery/img/logo820.png"
    desc = "Create timelock-based recovery solutions."
    has_blueprint = True
    blueprint_module = "oren-z0.specterext.timelockrecovery.controller"
    encrypt_data = True

    devstatus = devstatus_alpha
    isolated_client = False

    # TODO: As more Services are integrated, we'll want more robust categorization and sorting logic
    sort_priority = 2

    # ServiceEncryptedStorage field names for this service
    # Those will end up as keys in a json-file
    SPECTER_WALLET_ALIAS = "wallet"

    reserved_address_names = [
        "Timelock Recovery Alert Address",
        "Timelock Recovery Cancellation Address"
    ]

    # There might be other callbacks you're interested in. Check the callbacks.py in the specter-desktop source.
    # if you are, create a method here which is "callback_" + callback_id

    @classmethod
    def deassociate_all_addresses(cls, wallet: Wallet):
        addresses = wallet.get_associated_addresses(cls.id)
        for addr_obj in addresses:
            wallet.deassociate_address(addr_obj.address)

    @classmethod
    def get_or_reserve_addresses(cls, wallet: Wallet):
        addresses = wallet.get_associated_addresses(cls.id)
        left_names = list(cls.reserved_address_names)[len(addresses):]
        index = wallet.address_index
        while left_names:
            index += 1 # Also skip first address, is it may have been given to someone.
            addr = wallet.get_address(index)
            addr_obj = wallet.get_address_obj(addr)
            if addr_obj.used or addr_obj.is_reserved:
                continue
            wallet.associate_address_with_service(address=addr, service_id=cls.id, label=f"Address #{index} - {left_names.pop(0)}")
            addresses.append(addr_obj)
        return addresses

    @classmethod
    def signhotwallet(cls, request_form, wallet):
        passphrase = request_form["passphrase"]
        psbt = json.loads(request_form["psbt"])
        current_psbt = wallet.PSBTCls(
            psbt["base64"],
            wallet.descriptor,
            wallet.network,
            devices=list(zip(wallet.keys, wallet._devices)),
        )
        b64psbt = str(current_psbt)
        device = request_form["device"]
        if "devices_signed" not in psbt or device not in psbt["devices_signed"]:
            try:
                # get device and sign with it
                signed_psbt = app.specter.device_manager.get_by_alias(
                    device
                ).sign_psbt(b64psbt, wallet, passphrase)
                raw = None
                if signed_psbt["complete"]:
                    raw = wallet.rpc.finalizepsbt(b64psbt)
                current_psbt.update(signed_psbt["psbt"], raw)
                signed_psbt = signed_psbt["psbt"]
                return current_psbt.to_dict(), signed_psbt
            except Exception as e:
                handle_exception(e)
                flash(_("Failed to sign PSBT: {}").format(e), "error")
                return psbt, None
        else:
            flash(_("Device already signed the PSBT"), "error")
            return psbt, None

    @classmethod
    def get_recovery_plans(cls):
        wrapper = TimelockrecoveryService.get_current_user_service_data().get("recovery_plans", {"version": 1, "plans": []})
        return wrapper["plans"]

    @classmethod
    def set_recovery_plans(cls, plans):
        wrapper = TimelockrecoveryService.get_current_user_service_data().get("recovery_plans", {"version": 1, "plans": []})
        wrapper["plans"] = plans
        TimelockrecoveryService.update_current_user_service_data({ "recovery_plans": wrapper })
