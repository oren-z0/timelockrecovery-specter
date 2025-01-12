from datetime import datetime
import logging
import random
import json
from binascii import b2a_base64
import uuid
from flask import redirect, render_template, request, url_for
from flask import current_app as app
from flask_login import login_required, current_user
from flask_babel import lazy_gettext as _
from embit.transaction import Transaction, TransactionInput, TransactionOutput, Script
from embit.psbt import PSBT

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
@user_secret_decrypted_required
def step1_post():
    verify_not_liquid()
    current_user.add_service(TimelockrecoveryService.id)
    return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step1_get"))

@timelockrecovery_endpoint.route("/step1", methods=["GET"])
@login_required
@user_secret_decrypted_required
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
@user_secret_decrypted_required
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

    reserved_address = TimelockrecoveryService.get_or_reserve_addresses(wallet)[0]

    return render_template(
        "timelockrecovery/step2.jinja",
        wallet=wallet,
        specter=app.specter,
        rand=rand,
        reserved_address=reserved_address,
    )

@timelockrecovery_endpoint.route("/step3", methods=["POST"])
@login_required
@user_secret_decrypted_required
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
    request_data = json.loads(request.form["request_data"])

    if action == "prepare":
        psbt_creator = PsbtCreator(
            app.specter, wallet, "json", request_json=request_data["alert_psbt_request_json"]
        )
        psbt_creator.kwargs["readonly"] = True
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
        psbt, signed_psbt = TimelockrecoveryService.signhotwallet(request.form, wallet)
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
@user_secret_decrypted_required
def step4_post():
    verify_not_liquid()
    wallet_alias = request.args.get('wallet')
    wallet: Wallet = current_user.wallet_manager.get_by_alias(wallet_alias)
    if not wallet:
        raise SpecterError(
            "Wallet could not be loaded. Are you connected with Bitcoin Core?"
        )

    action = request.form.get("action")
    request_data = json.loads(request.form["request_data"])

    if action == "prepare":
        alert_raw = request.form["alert_raw"]
        alert_tx = Transaction.from_string(alert_raw)
        alert_txid = alert_tx.txid()

        sequence = round((request_data["timelock_days"] * 24 * 60 - (11 * 10 / 2)) * 60 / 512)

        recovery_psbt = PSBT(Transaction(
            version=2,
            vin=[TransactionInput(
                txid=alert_txid,
                vout=0,
                sequence=sequence,
            )],
            vout=[TransactionOutput(amount_sats, Script.from_address(address)) for (address, amount_sats) in request_data["recovery_recipients"]],
            locktime=0,
        ))
        recovery_psbt.inputs[0].witness_utxo = alert_tx.vout[0]

        recovery_psbt = wallet.PSBTCls(
            recovery_psbt.to_base64(),
            wallet.descriptor,
            wallet.network,
            devices=list(zip(wallet.keys, wallet.devices)),
        )

        request_data["alert_raw"] = alert_raw
        request_data["alert_txid"] = alert_txid.hex()

        return render_template(
            "timelockrecovery/step4.jinja",
            request_data=request_data,
            psbt=recovery_psbt.to_dict(),
            wallet=wallet,
            specter=app.specter,
            rand=rand,
        )
    if action == "signhotwallet":
        psbt, signed_psbt = TimelockrecoveryService.signhotwallet(request.form, wallet)
        return render_template(
            "timelockrecovery/step4.jinja",
            request_data=request_data,
            signed_psbt=signed_psbt,
            psbt=psbt,
            wallet=wallet,
            specter=app.specter,
            rand=rand,
        )
    raise SpecterError("Unexpected action")

@timelockrecovery_endpoint.route("/step4", methods=["GET"])
@login_required
def step4_get():
    wallet_alias = request.args.get('wallet')
    if wallet_alias:
        return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step2") + f"?wallet={wallet_alias}")
    return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step1_get"))

@timelockrecovery_endpoint.route("/step5", methods=["POST"])
@login_required
@user_secret_decrypted_required
def step5_post():
    verify_not_liquid()
    wallet_alias = request.args.get('wallet')
    wallet: Wallet = current_user.wallet_manager.get_by_alias(wallet_alias)
    if not wallet:
        raise SpecterError(
            "Wallet could not be loaded. Are you connected with Bitcoin Core?"
        )

    action = request.form.get("action")
    request_data = json.loads(request.form["request_data"])

    if action == "prepare":
        alert_tx = Transaction.from_string(request_data["alert_raw"])

        cancellation_address = TimelockrecoveryService.get_or_reserve_addresses(wallet)[1].address

        cancellation_psbt = PSBT(Transaction(
            version=2,
            vin=[TransactionInput(
                txid=alert_tx.txid(),
                vout=0,
                sequence=0xfffffffd,
            )],
            vout=[TransactionOutput(request_data['cancellation_sats'], Script.from_address(cancellation_address))],
            locktime=0,
        ))
        cancellation_psbt.inputs[0].witness_utxo = alert_tx.vout[0]

        cancellation_psbt = wallet.PSBTCls(
            cancellation_psbt.to_base64(),
            wallet.descriptor,
            wallet.network,
            devices=list(zip(wallet.keys, wallet.devices)),
        )

        recovery_raw = request.form["recovery_raw"]
        request_data["recovery_raw"] = recovery_raw
        request_data["recovery_txid"] = Transaction.from_string(recovery_raw).txid().hex()

        return render_template(
            "timelockrecovery/step5.jinja",
            request_data=request_data,
            psbt=cancellation_psbt.to_dict(),
            wallet=wallet,
            specter=app.specter,
            rand=rand,
        )
    if action == "signhotwallet":
        psbt, signed_psbt = TimelockrecoveryService.signhotwallet(request.form, wallet)
        return render_template(
            "timelockrecovery/step5.jinja",
            request_data=request_data,
            signed_psbt=signed_psbt,
            psbt=psbt,
            wallet=wallet,
            specter=app.specter,
            rand=rand,
        )
    raise SpecterError("Unexpected action")

@timelockrecovery_endpoint.route("/step5", methods=["GET"])
@login_required
def step5_get():
    wallet_alias = request.args.get('wallet')
    if wallet_alias:
        return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step2") + f"?wallet={wallet_alias}")
    return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step1_get"))

@timelockrecovery_endpoint.route("/step6", methods=["POST"])
@login_required
@user_secret_decrypted_required
def step6_post():
    verify_not_liquid()
    wallet_alias = request.args.get('wallet')
    wallet: Wallet = current_user.wallet_manager.get_by_alias(wallet_alias)
    if not wallet:
        raise SpecterError(
            "Wallet could not be loaded. Are you connected with Bitcoin Core?"
        )
    plan_id = str(uuid.uuid4())
    request_data = json.loads(request.form["request_data"])
    cancellation_raw = request.form.get("cancellation_raw", "")
    request_data["cancellation_raw"] = cancellation_raw
    request_data["cancellation_txid"] = "" if cancellation_raw == "" else Transaction.from_string(cancellation_raw).txid().hex()
    request_data["wallet_alias"] = wallet_alias
    request_data["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    request_data["id"] = plan_id

    plans = TimelockrecoveryService.get_recovery_plans()
    if plans and isinstance(plans[0], str):
        plans = []
    plans.append(request_data)
    TimelockrecoveryService.set_recovery_plans(plans)

    return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name() }.plans") + f"?plan={plan_id}")

@timelockrecovery_endpoint.route("/step6", methods=["GET"])
@login_required
def step6_get():
    wallet_alias = request.args.get('wallet')
    if wallet_alias:
        return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step2") + f"?wallet={wallet_alias}")
    return redirect(url_for(f"{ TimelockrecoveryService.get_blueprint_name()}.step1_get"))

@timelockrecovery_endpoint.route("/plans", methods=["GET"])
@login_required
@user_secret_decrypted_required
def plans():
    plans = []
    for plan in TimelockrecoveryService.get_recovery_plans():
        try:
            wallet = current_user.wallet_manager.get_by_alias(plan["wallet_alias"] + "x")
        except SpecterError as e:
            logger.warning("Failed to find wallet of recovery plan - it may have been deleted.", e)
            wallet = None
        plans.append({
            "id": plan["id"],
            "wallet_alias": plan["wallet_alias"],
            "wallet": wallet,
            "created_at": plan["created_at"]
        })
    return render_template(
        "timelockrecovery/plans.jinja",
        plans=plans,
    )

@timelockrecovery_endpoint.route("/plans/<plan_id>", methods=["GET"])
@login_required
@user_secret_decrypted_required
def plan_get(plan_id):
    plans = [plan for plan in TimelockrecoveryService.get_recovery_plans() if plan["id"] == plan_id]
    if not plans:
        return { "error": "Plan does not exist" }, 404
    plan = plans[0]
    try:
        wallet = current_user.wallet_manager.get_by_alias(plan["wallet_alias"])
        plan["wallet_name"] = wallet.name
    except SpecterError as e:
        logger.warning("Failed to find wallet of recovery plan - it may have been deleted.", e)
    return { "plan": plan }

@timelockrecovery_endpoint.route("/plans/<plan_id>", methods=["DELETE"])
@login_required
@user_secret_decrypted_required
def plan_delete(plan_id):
    plans = [plan for plan in TimelockrecoveryService.get_recovery_plans() if plan["id"] != plan_id]
    TimelockrecoveryService.set_recovery_plans(plans)
    return { "ok": True }

@timelockrecovery_endpoint.route("/settings", methods=["GET"])
@login_required
@user_secret_decrypted_required
def settings_get():
    return render_template(
        "timelockrecovery/settings.jinja",
        show_menu="yes" if current_user.has_service(TimelockrecoveryService.id) else "no",
        has_recovery_plans=len(TimelockrecoveryService.get_recovery_plans()) > 0,
        cookies=request.cookies,
    )

@timelockrecovery_endpoint.route("/settings", methods=["POST"])
@login_required
def settings_post():
    show_menu = request.form["show_menu"]
    if show_menu == "yes":
        current_user.add_service(TimelockrecoveryService.id)
    else:
        current_user.remove_service(TimelockrecoveryService.id)
    return redirect(url_for(f"{TimelockrecoveryService.get_blueprint_name()}.settings_get"))

@timelockrecovery_endpoint.route("/remove_extension", methods=["POST"])
@login_required
@user_secret_decrypted_required
def remove_extension_post():
    if len(TimelockrecoveryService.get_recovery_plans()) > 0:
        return redirect(url_for(f"{TimelockrecoveryService.get_blueprint_name()}.settings_get"))
    for wallet in current_user.wallet_manager.wallets.values():
        TimelockrecoveryService.deassociate_all_addresses(wallet)
    current_user.remove_service(TimelockrecoveryService.id)
    return redirect(url_for("wallets_endpoint.wallets_overview"))

@timelockrecovery_endpoint.route("/remove_extension", methods=["GET"])
@login_required
def remove_extension_get():
    return redirect(url_for("wallets_endpoint.wallets_overview"))


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
    single_input_extra_vsize = (psbt_creator.psbt_as_object.extra_input_weight + 3) / 4

    try:
        recovery_recipients = [Script.from_address(address) for address in request.json["recovery_recipients"]]
    except:
        return { "error": "Invalid Bitcoin address" }
    raw_recovery_tx = Transaction(
        version=2,
        vin=[TransactionInput(
            txid=bytes.fromhex(psbt["tx"]["txid"]),
            vout=0,
            sequence=0xfffffffd,
        )],
        vout=[TransactionOutput(
            0,
            address,
        ) for address in recovery_recipients],
        locktime=0,
    )
    raw_recovery_tx_size = len(raw_recovery_tx.serialize())

    cancellation_address_string = TimelockrecoveryService.get_or_reserve_addresses(wallet)[1].address
    try:
        cancellation_address = Script.from_address(cancellation_address_string)
    except:
        return { "error": f"Invalid Bitcoin address: {cancellation_address_string}" }

    raw_cancellation_tx = Transaction(
        version=2,
        vin=[TransactionInput(
            txid=bytes.fromhex(psbt["tx"]["txid"]),
            vout=0,
            sequence=0xfffffffd,
        )],
        vout=[TransactionOutput(
            0,
            cancellation_address,
        )],
        locktime=0,
    )
    raw_cancellation_tx_size = len(raw_cancellation_tx.serialize())

    return {
        "psbt": psbt,
        "recovery_transaction_vsize": raw_recovery_tx_size + single_input_extra_vsize,
        "cancellation_transaction_vsize": raw_cancellation_tx_size + single_input_extra_vsize,
    }

@timelockrecovery_endpoint.route("/combine_nonpending_psbt/<wallet_alias>", methods=["POST"])
@login_required
def combine_nonpending_psbt(wallet_alias):
    wallet: Wallet = app.specter.wallet_manager.get_by_alias(wallet_alias)
    # only post requests
    # FIXME: ugly...
    psbts = [request.form.get("psbt0").strip(), request.form.get("psbt1").strip()]
    raw = {}
    combined = None

    for i, psbt in enumerate(psbts):
        if not psbt:
            return _("Cannot parse empty data as PSBT"), 500
        if "UR:BYTES/" in psbt.upper():
            psbt = bcur2base64(psbt).decode()

        # if electrum then it's base43
        try:
            decoded = b43_decode(psbt)
            if decoded[:5] in [b"psbt\xff", b"pset\xff"]:
                psbt = b2a_base64(decoded).decode()
            else:
                psbt = decoded.hex()
        except:
            pass

        psbts[i] = psbt
        # psbt should start with cHNi
        # if not - maybe finalized hex tx
        if not psbt.startswith("cHNi") and not psbt.startswith("cHNl"):
            raw["hex"] = psbt
            combined = psbts[1 - i]
            # check it's hex
            try:
                bytes.fromhex(psbt)
            except:
                return _("Invalid transaction format"), 500

    try:
        if "hex" in raw:
            raw["complete"] = True
            raw["psbt"] = combined
        else:
            combined = app.specter.combine(psbts)
            raw = app.specter.finalize(combined)
            if "psbt" not in raw:
                raw["psbt"] = combined
        # PSBT is not in wallet.pending_psbts
        psbt = wallet.PSBTCls(
            combined,
            wallet.descriptor,
            wallet.network,
            devices=list(zip(wallet.keys, wallet.devices)),
        ).to_dict()
        raw["devices"] = psbt["devices_signed"]
    except RpcError as e:
        return e.error_msg, e.status_code
    except Exception as e:
        handle_exception(e)
        return _("Unknown error: {}").format(e), 500
    return json.dumps(raw)
