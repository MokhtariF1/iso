# from zarinpal import ZarinPal
from config import settings
from database import get_db
from models import Payment
import requests


def initiate_payment(amount, description):
    authority = None
    payment_url = None
    try:
        # zarinpal = ZarinPal(settings.config)
        # response = zarinpal.payments.create({
        #     "amount": amount,
        #     "callback_url": settings.domain + "api/payments/success",
        #     "description": description,
        # })
        #
        # print("Payment created successfully:", response)
        data = {
            "merchant": settings.merchant,
            "amount": amount,
            "description": description,
            "callback_url": settings.callback_url,
        }
        response = requests.post(f"{settings.zarinpal}pg/v4/payment/request.json", json=data)
        response = response.json()
        if "data" in response and "authority" in response["data"]:
            authority = response["data"]["authority"]
            payment_url = f"{settings.zarinpal}pg/StartPay/{authority}"
            print("Payment URL:", payment_url)
        else:
            print("Authority not found in response.")


    except Exception as e:
        print("Error during payment creation:", e)
    return {"authority": authority, "payment_url": payment_url}


def get_amount_from_database(authority):
    db = next(get_db())
    pay = db.query(Payment).filter(Payment.authority == authority).first()
    if pay:
        return pay.amount
    else:
        return None


def verify_payment(authority, status):
    if status == "OK":
        amount = get_amount_from_database(authority)

        if amount:
            try:
                # zarinpal = ZarinPal(settings.config)
                # response = zarinpal.verifications.verify({
                #     "amount": amount,
                #     "authority": authority,
                # })
                data = {
                    "merchant_id": settings.merchant,
                    "amount": amount,
                    "authority": authority,
                }
                response = requests.post(f"{settings.zarinpal}pg/v4/payment/verify.json", json=data)
                response = response.json()
                if response["data"]["code"] == 100:
                    print("Payment Verified:")
                    print("Reference ID:", response["data"]["ref_id"])
                    print("Card PAN:", response["data"]["card_pan"])
                    print("Fee:", response["data"]["fee"])
                    return response
                elif response["data"]["code"] == 101:
                    print("Payment already verified.")
                    return None
                else:
                    print("Transaction failed with code:", response["data"]["code"])
                    return None
            except Exception as e:
                print("Payment Verification Failed:", e)
                return None
        else:
            print("No Matching Transaction Found For This Authority Code.")
            return None
    else:
        print("Transaction was cancelled or failed.")
        return None


# def injquery(authority, status):
#     if status == "OK":
#         amount = get_amount_from_database(authority)
#
#         if amount:
#             try:
#                 zarinpal = ZarinPal(settings.config)
#                 response = zarinpal.inquiries.inquire({
#                     "authority": authority,
#                 })
#
#                 return response
#             except Exception as e:
#                 print("Payment Verification Failed:", e)
#         else:
#             print("No Matching Transaction Found For This Authority Code.")
#     else:
#         print("Transaction was cancelled or failed.")

# if __name__ == "__main__":
#     # payment = initiate_payment()
#     # verify_payment("S000000000000000000000000000000gooyl", 'OK')
#     injquery("S000000000000000000000000000000wllzn", 'OK')
