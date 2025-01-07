"""
server.py
Stripe Sample.
Python 3.6 or newer required.
"""
import os
from flask import Flask, jsonify, redirect, request
import traceback
import stripe
import json
from flask_cors import CORS

# This is your test secret API key.

app = Flask(__name__,
            static_url_path='',
            static_folder='public')
CORS(app)

def read_config():
    f = open('secrets/config.json')
    return json.load(f)

YOUR_DOMAIN = 'http://localhost:3000'

conf = read_config()

stripe.api_key = conf["stripe"]["key"]

def get_product_info(product_id):
    try:
        # Retrieve the subscription using its ID
        product = stripe.Product.retrieve(product_id)
        return product
    except stripe.error.StripeError as e:
        # Handle errors from the Stripe API
        print("An error occurred:", e.user_message)
    except Exception as e:
        # Handle generic errors
        print("An unexpected error occurred:", str(e))

def get_subscription_info(subscription_id):
    try:
        # Retrieve the subscription using its ID
        subscription = stripe.Subscription.retrieve(subscription_id)
        return subscription
    except stripe.error.StripeError as e:
        # Handle errors from the Stripe API
        print("An error occurred:", e.user_message)
    except Exception as e:
        # Handle generic errors
        print("An unexpected error occurred:", str(e))

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        session = stripe.checkout.Session.create(
            ui_mode = 'embedded',
            line_items=[
                {
                    # Provide the exact Price ID (for example, pr_1234) of the product you want to sell
                    'price': conf["stripe"]["price_id_1"],
                    'quantity': 1,
                },
            ],
            mode='subscription',
            return_url=YOUR_DOMAIN + '/subscription?session_id={CHECKOUT_SESSION_ID}',
        )
    except Exception as e:
        return str(e)

    return jsonify(clientSecret=session.client_secret)

@app.route('/session-status', methods=['GET'])
def session_status():
  session = stripe.checkout.Session.retrieve(request.args.get('session_id'))
  #print(session)
  subscription_info = get_subscription_info(session["subscription"])
  product_info = get_product_info(subscription_info["plan"]["product"])
  
  return jsonify(status=session["status"], payment=session["payment_status"], customer=session["customer_details"], date=session["created"], amount=session["amount_total"], product_name=product_info["name"], product_description=product_info["description"])


# New endpoint to capture success data
@app.route('/checkout-success', methods=['GET'])
def checkout_success():
    session_id = request.args.get('session_id')
    
    if session_id:
        # Retrieve the session data from Stripe
        session = stripe.checkout.Session.retrieve(session_id)
        print("Session Data:", session)  # Print the session data to the console

        # Log specific session details if needed
        customer_email = session.get('customer_details', {}).get('email')
        subscription_id = session.get('subscription')
        print("Customer Email:", customer_email)
        print("Subscription ID:", subscription_id)
        
        # Return a response with session data
        return jsonify({
            "session_id": session_id,
            "customer_email": customer_email,
            "subscription_id": subscription_id
        })
    
    return jsonify({"error": "Session ID not found"}), 400

if __name__ == '__main__':
    app.run(port=4242)