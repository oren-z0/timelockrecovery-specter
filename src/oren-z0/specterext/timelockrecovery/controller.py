import logging
import random
import json
from binascii import b2a_base64
from flask import redirect, render_template, request, url_for, flash, abort
from flask import current_app as app
from flask_login import login_required, current_user
from flask_babel import lazy_gettext as _

from cryptoadvance.specter.specter import Specter
from cryptoadvance.specter.services.controller import user_secret_decrypted_required
from cryptoadvance.specter.user import User
from cryptoadvance.specter.wallet import Wallet
from cryptoadvance.specter.specter_error import SpecterError, handle_exception
from cryptoadvance.specter.commands.psbt_creator import PsbtCreator
from cryptoadvance.specter.helpers import bcur2base64
from cryptoadvance.specter.util.base43 import b43_decode
from cryptoadvance.specter.rpc import RpcError
from .service import TimelockrecoveryService


rand = random.randint(0, 1e32)

logger = logging.getLogger(__name__)

timelockrecovery_endpoint = TimelockrecoveryService.blueprint

def ext() -> TimelockrecoveryService:
    ''' convenience for getting the extension-object'''
    return app.specter.ext["timelockrecovery"]

def specter() -> Specter:
    ''' convenience for getting the specter-object'''
    return app.specter

def verify_not_liquid():
    if app.specter.is_liquid:
        raise SpecterError("Timelock Recovery does not support Liquid")


@timelockrecovery_endpoint.route("/")
@login_required
def index():
    verify_not_liquid()
    return render_template(
        "timelockrecovery/index.jinja",
    )

@timelockrecovery_endpoint.route("/step1", methods=["POST"])
@login_required
def step1_post():
    verify_not_liquid()
    user = app.specter.user_manager.get_user()
    user.add_service(TimelockrecoveryService.id)
    return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step1_get"))

@timelockrecovery_endpoint.route("/step1", methods=["GET"])
@login_required
def step1_get():
    verify_not_liquid()
    wallet_names = sorted(current_user.wallet_manager.wallets.keys())
    wallets = [current_user.wallet_manager.wallets[name] for name in wallet_names]
    return render_template(
        "timelockrecovery/step1.jinja",
        wallets=wallets,
    )

@timelockrecovery_endpoint.route("/step2", methods=["GET"])
@login_required
def step2():
    verify_not_liquid()
    wallet_alias = request.args.get('wallet')
    wallet: Wallet = current_user.wallet_manager.get_by_alias(wallet_alias)
    if not wallet:
        raise SpecterError(
            "Wallet could not be loaded. Are you connected with Bitcoin Core?"
        )
    # update balances in the wallet
    wallet.update_balance()
    # update utxo list for coin selection
    wallet.check_utxo()

    reserved_address = TimelockrecoveryService.get_or_reserve_address(wallet)

    return render_template(
        "timelockrecovery/step2.jinja",
        wallet=wallet,
        specter=app.specter,
        rand=rand,
        reserved_address=reserved_address,
    )

@timelockrecovery_endpoint.route("/step3", methods=["POST"])
@login_required
def step3_post():
    verify_not_liquid()
    wallet_alias = request.args.get('wallet')
    wallet: Wallet = current_user.wallet_manager.get_by_alias(wallet_alias)
    if not wallet:
        raise SpecterError(
            "Wallet could not be loaded. Are you connected with Bitcoin Core?"
        )
    # update balances in the wallet
    wallet.update_balance()
    # update utxo list for coin selection
    wallet.check_utxo()

    action = request.form.get("action")

    if action == "prepare":
        request_data = json.loads(request.form["data"])
        psbt_creator = PsbtCreator(
            app.specter, wallet, "json", request_json=request_data["alert_psbt_request_json"]
        )
        psbt = psbt_creator.create_psbt(wallet)

        return render_template(
            "timelockrecovery/step3.jinja",
            request_data=request_data,
            psbt=psbt,
            wallet=wallet,
            specter=app.specter,
            rand=rand,
        )
    if action == "signhotwallet":
        request_data = json.loads(request.form["request_data"])
        passphrase = request.form["passphrase"]
        psbt = json.loads(request.form["psbt"])
        current_psbt = wallet.PSBTCls(
            psbt["base64"],
            wallet.descriptor,
            wallet.network,
            devices=list(zip(wallet.keys, wallet._devices)),
        )
        b64psbt = str(current_psbt)
        device = request.form["device"]
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
                psbt = current_psbt.to_dict()
            except Exception as e:
                handle_exception(e)
                signed_psbt = None
                flash(_("Failed to sign PSBT: {}").format(e), "error")
        else:
            signed_psbt = None
            flash(_("Device already signed the PSBT"), "error")
        return render_template(
            "timelockrecovery/step3.jinja",
            request_data=request_data,
            signed_psbt=signed_psbt,
            psbt=psbt,
            wallet=wallet,
            specter=app.specter,
            rand=rand,
        )
    raise SpecterError("Unexpected action")


@timelockrecovery_endpoint.route("/step3", methods=["GET"])
@login_required
def step3_get():
    wallet_alias = request.args.get('wallet')
    if wallet_alias:
        return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step2") + f"?wallet={wallet_alias}")
    return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step1_get"))

@timelockrecovery_endpoint.route("/step4", methods=["POST"])
@login_required
def step4_post():
    verify_not_liquid()
    wallet_alias = request.args.get('wallet')
    wallet: Wallet = current_user.wallet_manager.get_by_alias(wallet_alias)
    if not wallet:
        raise SpecterError(
            "Wallet could not be loaded. Are you connected with Bitcoin Core?"
        )
    # update balances in the wallet
    wallet.update_balance()
    # update utxo list for coin selection
    wallet.check_utxo()
    return "<pre style=\"font-size: 2rem;\">hi \n" + json.dumps(json.loads(request.form["request_data"]), indent=2).replace('<', '&lt;') + "\n" + json.dumps(json.loads(request.form["alert_psbt"]), indent=2).replace('<', '&lt;') + "\n" + request.form["alert_raw"] + "</pre>"

@timelockrecovery_endpoint.route("/step4", methods=["GET"])
@login_required
def step4_get():
    wallet_alias = request.args.get('wallet')
    if wallet_alias:
        return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step2") + f"?wallet={wallet_alias}")
    return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step1_get"))


@timelockrecovery_endpoint.route("/transactions")
@login_required
def transactions():
    # The wallet currently configured for ongoing autowithdrawals
    wallet: Wallet = TimelockrecoveryService.get_associated_wallet()

    return render_template(
        "timelockrecovery/transactions.jinja",
        wallet=wallet,
        services=app.specter.service_manager.services,
    )


@timelockrecovery_endpoint.route("/settings", methods=["GET"])
@login_required
def settings_get():
    associated_wallet: Wallet = TimelockrecoveryService.get_associated_wallet()

    # Get the user's Wallet objs, sorted by Wallet.name
    wallet_names = sorted(current_user.wallet_manager.wallets.keys())
    wallets = [current_user.wallet_manager.wallets[name] for name in wallet_names]

    return render_template(
        "timelockrecovery/settings.jinja",
        associated_wallet=associated_wallet,
        wallets=wallets,
        cookies=request.cookies,
    )

@timelockrecovery_endpoint.route("/settings", methods=["POST"])
@login_required
def settings_post():
    show_menu = request.form["show_menu"]
    user = app.specter.user_manager.get_user()
    if show_menu == "yes":
        user.add_service(TimelockrecoveryService.id)
    else:
        user.remove_service(TimelockrecoveryService.id)
    used_wallet_alias = request.form.get("used_wallet")
    if used_wallet_alias != None:
        wallet = current_user.wallet_manager.get_by_alias(used_wallet_alias)
        TimelockrecoveryService.set_associated_wallet(wallet)
    return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.settings_get"))

@timelockrecovery_endpoint.route("/create_alert_psbt_recovery_vsize/<wallet_alias>", methods=["POST"])
@login_required
def create_alert_psbt_recovery_vsize(wallet_alias):
    wallet: Wallet = current_user.wallet_manager.get_by_alias(wallet_alias)
    if not wallet:
        raise SpecterError(
            "Wallet could not be loaded. Are you connected with Bitcoin Core?"
        )
    psbt_creator = PsbtCreator(
        app.specter, wallet, "json", request_json=request.json["alert_psbt_request_json"]
    )
    psbt_creator.kwargs["readonly"] = True
    psbt = psbt_creator.create_psbt(wallet)

    raw_recovery_tx_hex = app.specter.rpc.createrawtransaction(
        [{"txid": psbt["tx"]["txid"], "vout": 0}],
        [{address: 0} for address in request.json["recovery_recipients"]],
        0,
        True
    )
    raw_recovery_tx_size = len(raw_recovery_tx_hex) / 2
    return {
        "psbt": psbt,
        "recovery_transaction_vsize": raw_recovery_tx_size + (psbt_creator.psbt_as_object.extra_input_weight + 3) / 4.
    }

@timelockrecovery_endpoint.route("/delete_psbt/<wallet_alias>/<txid>", methods=["POST"])
@login_required
def delete_psbt(wallet_alias, txid):
    wallet: Wallet = current_user.wallet_manager.get_by_alias(wallet_alias)
    if not wallet:
        raise SpecterError(
            "Wallet could not be loaded. Are you connected with Bitcoin Core?"
        )
    wallet.delete_pending_psbt(txid)
    return {}
