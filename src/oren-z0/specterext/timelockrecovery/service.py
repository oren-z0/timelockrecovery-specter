from base64 import b64decode
import json
import logging

from cryptoadvance.specter.services.service import Service, devstatus_alpha, devstatus_prod, devstatus_beta
# A SpecterError can be raised and will be shown to the user as a red banner
from cryptoadvance.specter.specter_error import SpecterError, handle_exception
from flask import current_app as app, flash
from flask_babel import lazy_gettext as _
from cryptoadvance.specter.wallet import Wallet
from flask_apscheduler import APScheduler
from embit.psbt import PSBT

logger = logging.getLogger(__name__)

class TimelockrecoveryService(Service):
    id = "timelockrecovery"
    name = "Timelock Recovery"
    icon = "timelockrecovery/img/logo160.png"
    logo = "timelockrecovery/img/logo820.png"
    desc = "Create timelock-based recovery solutions."
    has_blueprint = True
    blueprint_module = "oren-z0.specterext.timelockrecovery.controller"

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

    def callback_after_serverpy_init_app(self, scheduler: APScheduler):
        def every5seconds(hello, world="world"):
            with scheduler.app.app_context():
                print(f"Called {hello} {world} every5seconds")
        # Here you can schedule regular jobs. triggers can be one of "interval", "date" or "cron"
        # Examples:
        # interval: https://apscheduler.readthedocs.io/en/3.x/modules/triggers/interval.html
        # scheduler.add_job("every5seconds4", every5seconds, trigger='interval', seconds=5, args=["hello"])

        # Date: https://apscheduler.readthedocs.io/en/3.x/modules/triggers/date.html
        # scheduler.add_job("MyId", my_job, trigger='date', run_date=date(2009, 11, 6), args=['text'])

        # cron: https://apscheduler.readthedocs.io/en/3.x/modules/triggers/cron.html
        # sched.add_job("anotherID", job_function, trigger='cron', day_of_week='mon-fri', hour=5, minute=30, end_date='2014-05-30')

        # Maybe you should store the scheduler for later use:
        self.scheduler = scheduler

    # There might be other callbacks you're interested in. Check the callbacks.py in the specter-desktop source.
    # if you are, create a method here which is "callback_" + callback_id

    @classmethod
    def get_associated_wallet(cls) -> Wallet:
        """Get the Specter `Wallet` that is currently associated with this service"""
        service_data = cls.get_current_user_service_data()
        if not service_data or cls.SPECTER_WALLET_ALIAS not in service_data:
            # Service is not initialized; nothing to do
            return
        try:
            return app.specter.wallet_manager.get_by_alias(
                service_data[cls.SPECTER_WALLET_ALIAS]
            )
        except SpecterError as e:
            logger.debug(e)
            # Referenced an unknown wallet
            # TODO: keep ignoring or remove the unknown wallet from service_data?
            return

    @classmethod
    def set_associated_wallet(cls, wallet: Wallet):
        """Set the Specter `Wallet` that is currently associated with this Service"""
        cls.update_current_user_service_data({cls.SPECTER_WALLET_ALIAS: wallet.alias})

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
    def add_prev_tx_to_psbt(cls, psbt_base64, prev_tx, input_index=0, utxo_index=0):
        psbt = PSBT.from_base64(psbt_base64)
        psbt.inputs[input_index].witness_utxo = prev_tx.vout[utxo_index]
        return psbt

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
