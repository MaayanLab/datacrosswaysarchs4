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

YOUR_DOMAIN = 'http://localhost:4242'

conf = read_config()

stripe.api_key = conf["stripe"]["key"]


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    'price': conf["stripe"]["price_id_1"],
                    'quantity': 1,
                },
            ],
            mode="subscription",
            success_url=YOUR_DOMAIN + '/checkout-success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=YOUR_DOMAIN + '?canceled=true',
            automatic_tax={'enabled': False},
        )
    except Exception as e:
        return str(e)

    return redirect(checkout_session.url, code=303)


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