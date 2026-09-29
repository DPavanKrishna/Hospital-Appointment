import firebase_admin
from Security_utils import hash_password, verify_password, create_appointment_signature, verify_appointment_integrity, DigitalSignatureManager
from crypto_utils import (
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    rsa_encrypt_key,
    rsa_decrypt_key
)
from Security_utils import encode_base64, decode_base64

sig_manager = DigitalSignatureManager()
from firebase_admin import credentials, auth, firestore
from flask import Flask, request, redirect, render_template, session, url_for, jsonify, abort
import random, time, requests


FIREBASE_API_KEY = "AIzaSyB_ZvibhLwroPxFMqxKOUIX-aNwyJBM58U"

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db = firestore.client()


app = Flask(__name__)
app.secret_key = "super-secret-key"


otp_store = {}


# ACL 
ACL = {
    "patient": {
        "appointments": ["view_own", "create"],
        "users": [],
        "system_stats": []
    },
    "doctor": {
        "appointments": ["view_own", "update"],
        "users": [],
        "system_stats": []
    },
    "admin": {
        "appointments": ["view_all"],
        "users": ["view_all"],
        "system_stats": ["view"]
    }
}

def check_acl_permission(resource, action):
    role = session.get("role")
    if not role:
        return False, redirect(url_for("login"))
    permissions = ACL.get(role, {}).get(resource, [])
    if action not in permissions:
        error_msg = f"Access denied: {role} cannot {action} on {resource}"
        return False, abort(403, description=error_msg)
    return True, None
# ID GENERATOR
def generate_user_id(role):
    prefix_map = {
        "patient": "P",
        "doctor": "D",
        "admin": "A"
    }
    prefix = prefix_map.get(role, "U")
    counter_ref = db.collection("counters").document(f"{role}_counter")
    counter_doc = counter_ref.get()
    if counter_doc.exists:
        current_count = counter_doc.to_dict().get("count", 0)
    else:
        current_count = 0
    new_count = current_count + 1
    counter_ref.set({"count": new_count})
    return f"{prefix}{new_count:03d}"
# HOME
@app.route("/")
def home():
    if "user_id" in session:
        role = session.get("role")
        if role == "doctor":
            return redirect(url_for("doctor_dashboard"))
        elif role == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("patient_dashboard"))
    return render_template("home.html")

# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        user = auth.create_user(email=email, password=password)
        salt, hashed = hash_password(password)

        custom_id = generate_user_id(role)

        db.collection("users").document(user.uid).set({
            "id": user.uid,
            "custom_id": custom_id,  
            "name": name,
            "email": email,
            "role": role,
            "password_salt": salt,
            "password_hash": hashed
        })

        return redirect(url_for("login"))

    return render_template("register.html")

# LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        data = requests.post(url, json=payload).json()

        if "error" in data:
            return "Invalid credentials"

        uid = data["localId"]
        user = db.collection("users").document(uid).get().to_dict()
        if "password_salt" in user and "password_hash" in user:
            is_valid = verify_password(password, user["password_salt"], user["password_hash"])
            if not is_valid:
                return "Password verification failed"
        session.clear()
        session["temp_user"] = uid
        session["email"] = user["email"]
        session["role"] = user["role"]

        return redirect(url_for("generate_otp"))

    return render_template("login.html")

# OTP

@app.route("/generate-otp")
def generate_otp():
    uid = session.get("temp_user")
    otp = random.randint(100000, 999999)

    otp_store[uid] = {"otp": str(otp), "exp": time.time() + 300}
    print("OTP:", otp)

    return redirect(url_for("otp"))

@app.route("/otp", methods=["GET", "POST"])
def otp():
    uid = session.get("temp_user")
    if request.method == "POST":
        entered = request.form.get("otp")
        stored = otp_store.get(uid)

        if not stored or time.time() > stored["exp"]:
            return "OTP expired"

        if entered == stored["otp"]:
            user = db.collection("users").document(uid).get().to_dict()
            role = user["role"]
            custom_id = user.get("custom_id", uid)  

            session.clear()
            session["user_id"] = uid
            session["custom_id"] = custom_id  
            session["user_name"] = user.get("name", "User")
            session["role"] = role

            if role == "patient":
                session["patient_id"] = custom_id  
                redirect_url = url_for("patient_dashboard")
            elif role == "doctor":
                session["doctor_id"] = custom_id  
                redirect_url = url_for("doctor_dashboard")
            elif role == "admin":
                redirect_url = url_for("admin_dashboard")

            otp_store.pop(uid, None)
            return redirect(redirect_url)

        return "Invalid OTP"

    return render_template("otp.html")
# VIEW APPOINTMENT 
@app.route("/appointment/<appt_token>")
def view_appointment(appt_token):
 
    is_authorized, error_response = check_acl_permission("appointments", "view_own")
    if not is_authorized:
        return error_response
    
    patient_id = session.get("patient_id")  
    user_uid = session.get("user_id")       
    
    if not patient_id:
        return redirect(url_for("login"))

    try:
        token_data = decode_base64(appt_token)
        token_patient_id = token_data.get("patient_id")
        token_confirmation = token_data.get("confirmation_token")
    except Exception as e:
        print(f"Error decoding token: {e}")
        abort(400, description="Invalid token")

    if token_patient_id != patient_id:
        abort(403, description="Access denied: You can only view your own appointments")

    appointments = get_patient_appointments(patient_id)
    
    appointment = next((a for a in appointments if a.get("confirmation_token") == token_confirmation), None)
    
    if not appointment:
        print(f"Appointment not found. Token: {token_confirmation}")
        abort(404, description="Appointment not found")

    # Get doctor details
    doctor_uid = appointment.get("doctor_uid")
    if doctor_uid:
        try:
            doctor_doc = db.collection("users").document(doctor_uid).get()
            if doctor_doc.exists:
                doctor_data = doctor_doc.to_dict()
                appointment["doctor_name"] = doctor_data.get("name", "Unknown Doctor")
            else:
                appointment["doctor_name"] = "Unknown Doctor"
        except Exception as e:
            print(f"Error fetching doctor: {e}")
            appointment["doctor_name"] = "Unknown Doctor"
    else:
        appointment["doctor_name"] = "Unknown Doctor"

    # Get patient details
    if user_uid:
        try:
            patient_doc = db.collection("users").document(user_uid).get()
            if patient_doc.exists:
                patient_data = patient_doc.to_dict()
                appointment["patient_name"] = patient_data.get("name", "Unknown Patient")
            else:
                appointment["patient_name"] = "Unknown Patient"
        except Exception as e:
            print(f"Error fetching patient: {e}")
            appointment["patient_name"] = "Unknown Patient"
    else:
        appointment["patient_name"] = "Unknown Patient"

    return render_template("appoinment.html", appointment=appointment)

# UPDATE APPOINTMENT STATUS 
@app.route("/update_appointment_status/<appointment_id>", methods=["POST"])
def update_appointment_status(appointment_id):
    is_authorized, error_response = check_acl_permission("appointments", "update")
    if not is_authorized:
        return error_response
    try:
        data = request.get_json() or request.form
        new_status = data.get("status")
        if not new_status or new_status not in ["confirmed", "cancelled", "pending", "completed"]:
            return jsonify({"success": False, "error": "Invalid status"}), 400
        appt_ref = db.collection("appointments").document(appointment_id)
        appt_doc = appt_ref.get()
        if not appt_doc.exists:
            return jsonify({"success": False, "error": "Appointment not found"}), 404
        d = appt_doc.to_dict()
        
        # Decryption
        try:
            aes_key = rsa_decrypt_key(d["encrypted_key"])
            decrypted = aes_decrypt(d["ciphertext"], d["iv"], aes_key)
        except Exception as e:
            print(f"Decryption error: {e}")
            return jsonify({"success": False, "error": "Failed to decrypt appointment"}), 500

        doctor_id = session.get("doctor_id")
        if decrypted.get("doctor_id") != doctor_id:
            return jsonify({"success": False, "error": "Unauthorized: You can only update your own appointments"}), 403
        decrypted["status"] = new_status
        #Digital Signature
        sig_data = create_appointment_signature(decrypted, sig_manager)
        decrypted["signature"] = sig_data["signature"]
        decrypted["data_hash"] = sig_data["hash"]
        decrypted["signed_fields"] = sig_data["signed_fields"]
      
        aes_key = generate_aes_key()
        ciphertext, iv = aes_encrypt(decrypted, aes_key)
        encrypted_key = rsa_encrypt_key(aes_key)
        appt_ref.update({
            "ciphertext": ciphertext,
            "iv": iv,
            "encrypted_key": encrypted_key,
            "status": new_status,  
            "updated_at": time.time()
        })
        
        print(f"✓ Appointment {appointment_id} status updated to {new_status}")
        return jsonify({"success": True, "status": new_status})
        
    except Exception as e:
        print(f"Error updating appointment status: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
# BOOK APPOINTMENT 
@app.route("/book-appointment", methods=["GET", "POST"])
def book_appointment():
    is_authorized, error_response = check_acl_permission("appointments", "create")
    if not is_authorized:
        return error_response
    
    if request.method == "GET":
        doctors = []
        users = db.collection("users").where("role", "==", "doctor").stream()
        for doc in users:
            user_data = doc.to_dict()
            doctors.append({
                "id": doc.id,
                "custom_id": user_data.get("custom_id", doc.id),
                "name": user_data.get("name", "Unknown Doctor")
            })
        return render_template("book_appointment.html", doctors=doctors, session=session)

    data = request.get_json() or request.form
    doctor_uid = data.get("doctor")
    if not doctor_uid:
        return jsonify({"success": False, "error": "Doctor ID is required"}), 400
    doctor_doc = db.collection("users").document(doctor_uid).get()
    if not doctor_doc.exists:
        return jsonify({"success": False, "error": "Doctor not found"}), 404
    doctor_data = doctor_doc.to_dict()
    doctor_custom_id = doctor_data.get("custom_id", doctor_uid)
    appointment_data = {
        "patient_id": session["patient_id"],  
        "patient_uid": session["user_id"],     
        "doctor_id": doctor_custom_id,         
        "doctor_uid": doctor_uid,              
        "date": data.get("date"),
        "time": data.get("time"),
        "reason": data.get("reason"),
        "doctor_notes": data.get("notes", ""),
        "confirmation_token": f"APT-{random.randint(1000,9999)}",
        "status": "pending"
    }
    sig_data = create_appointment_signature(appointment_data, sig_manager)
    appointment_data["signature"] = sig_data["signature"]
    appointment_data["data_hash"] = sig_data["hash"]
    appointment_data["signed_fields"] = sig_data["signed_fields"]

    # Encryption
    aes_key = generate_aes_key()
    ciphertext, iv = aes_encrypt(appointment_data, aes_key)
    encrypted_key = rsa_encrypt_key(aes_key)

    # Base64 
    appt_token_encoded = encode_base64({
        "patient_id": appointment_data["patient_id"],
        "doctor_id": appointment_data["doctor_id"],
        "confirmation_token": appointment_data["confirmation_token"]
    })
    appointment_data["encoded_token"] = appt_token_encoded

    db.collection("appointments").add({
        "ciphertext": ciphertext,
        "iv": iv,
        "encrypted_key": encrypted_key,
        "status": "pending",
        "created_at": time.time(),
        "encoded_token": appt_token_encoded
    })

    print("✓ Appointment created with digital signature and Base64 token")
    return jsonify({"success": True, "appt_token": appt_token_encoded})
# MY APPOINTMENTS 
@app.route("/my-appointments")
def my_appointments():
    is_authorized, error_response = check_acl_permission("appointments", "view_own")
    if not is_authorized:
        return error_response
    role = session.get("role")
    if role == "patient":
        patient_id = session.get("patient_id")  
        if not patient_id:
            return jsonify({"success": False, "error": "Not authenticated"}), 401
        
        appointments = get_patient_appointments(patient_id)
        for appt in appointments:
            doctor_uid = appt.get("doctor_uid")
            
            if doctor_uid:
                try:
                    doctor_doc = db.collection("users").document(doctor_uid).get()
                    if doctor_doc.exists:
                        doctor_data = doctor_doc.to_dict()
                        appt["doctor_name"] = doctor_data.get("name", "Unknown Doctor")
                    else:
                        appt["doctor_name"] = "Unknown Doctor"
                except:
                    appt["doctor_name"] = "Unknown Doctor"
            else:
                appt["doctor_name"] = "Unknown Doctor"
        
        return jsonify({"success": True, "appointments": appointments})
    
    elif role == "doctor":
        doctor_id = session.get("doctor_id")
        if not doctor_id:
            return jsonify({"success": False, "error": "Not authenticated"}), 401
        
        appointments = get_doctor_appointments(doctor_id)
        return jsonify({"success": True, "appointments": appointments})
    
    else:
        return jsonify({"success": False, "error": "Invalid role"}), 403

def get_patient_appointments(patient_id):
    results = []
    docs = db.collection("appointments").stream()

    for doc in docs:
        d = doc.to_dict()
        try:
            aes_key = rsa_decrypt_key(d["encrypted_key"])
            decrypted = aes_decrypt(d["ciphertext"], d["iv"], aes_key)
        except Exception as e:
            results.append({
                "id": doc.id,
                "integrity_verified": False,
                "integrity_message": "Ciphertext tampered – decryption failed"
            })
            continue

        # Match by custom patient_id (P001, P002, etc.)
        if decrypted.get("patient_id") != patient_id:
            continue

        decrypted["id"] = doc.id
        is_valid, msg = (None, "Signature not present")
        if "signature" in decrypted and "data_hash" in decrypted:
            is_valid, msg = verify_appointment_integrity(
                decrypted, decrypted["signature"], decrypted["data_hash"], sig_manager
            )
        decrypted["integrity_verified"] = is_valid
        decrypted["integrity_message"] = msg
        results.append(decrypted)

    return results

def get_doctor_appointments(doctor_id):
    results = []
    docs = db.collection("appointments").stream()
    for doc in docs:
        try:
            d = doc.to_dict()
            aes_key = rsa_decrypt_key(d["encrypted_key"])
            decrypted = aes_decrypt(d["ciphertext"], d["iv"], aes_key)
            
            if decrypted.get("doctor_id") == doctor_id:
                decrypted["id"] = doc.id
                decrypted["status"] = decrypted.get("status", "pending").lower()
                patient_uid = decrypted.get("patient_uid")
                if patient_uid:
                    try:
                        patient_doc = db.collection("users").document(patient_uid).get()
                        if patient_doc.exists:
                            patient_data = patient_doc.to_dict()
                            decrypted["patient_name"] = patient_data.get("name", "Unknown")
                            decrypted["patient_custom_id"] = patient_data.get("custom_id", patient_uid)
                        else:
                            decrypted["patient_name"] = "Unknown"
                    except Exception as e:
                        print(f"Error fetching patient: {e}")
                        decrypted["patient_name"] = "Unknown"
                else:
                    patient_id = decrypted.get("patient_id")
                    if patient_id and not patient_id.startswith("P"):
                        try:
                            patient_doc = db.collection("users").document(patient_id).get()
                            if patient_doc.exists:
                                patient_data = patient_doc.to_dict()
                                decrypted["patient_name"] = patient_data.get("name", "Unknown")
                        except:
                            decrypted["patient_name"] = decrypted.get("patient_id", "Unknown")
                    else:
                        decrypted["patient_name"] = decrypted.get("patient_id", "Unknown")
                
                results.append(decrypted)
        except Exception as e:
            print(f"Error processing appointment: {e}")
            continue
    
    return results
# DASHBOARDS
@app.route("/patient")
def patient_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "patient":
        abort(403)
    return render_template("patient.html")

@app.route("/doctor")
def doctor_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "doctor":
        abort(403)
    doctor_id = session.get("doctor_id")  
    user_uid = session.get("user_id")     
    if not doctor_id or not user_uid:
        return redirect(url_for("login"))
    try:
        user_doc = db.collection("users").document(user_uid).get()
        if user_doc.exists:
            user = user_doc.to_dict()
            doctor_name = user.get("name", "Doctor")
        else:
            doctor_name = "Doctor"
    except Exception as e:
        print(f"Error fetching doctor details: {e}")
        doctor_name = "Doctor"
    appointments = get_doctor_appointments(doctor_id)
    return render_template("doctor.html", doctor_name=doctor_name, appointments=appointments)
@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        abort(403)
    return render_template("admin.html")
# ADMIN ENDPOINTS
@app.route("/api/admin/stats")
def admin_stats():
    is_authorized, error_response = check_acl_permission("system_stats", "view")
    if not is_authorized:
        return error_response
    try:
        users = db.collection("users").stream()
        total_patients = 0
        total_doctors = 0
        total_admins = 0
        for user in users:
            user_data = user.to_dict()
            role = user_data.get("role", "")
            if role == "patient":
                total_patients += 1
            elif role == "doctor":
                total_doctors += 1
            elif role == "admin":
                total_admins += 1
        appointments_ref = db.collection("appointments").stream()
        total_appointments = 0
        pending_appointments = 0
        confirmed_appointments = 0
        cancelled_appointments = 0
        completed_appointments = 0
        for appt_doc in appointments_ref:
            total_appointments += 1
            appt_data = appt_doc.to_dict()
            status = appt_data.get("status", "").lower()
            if not status:
                try:
                    aes_key = rsa_decrypt_key(appt_data.get("encrypted_key", ""))
                    decrypted = aes_decrypt(appt_data.get("ciphertext", ""), appt_data.get("iv", ""), aes_key)
                    status = decrypted.get("status", "pending").lower()
                except:
                    status = "pending"
            if status == "pending":
                pending_appointments += 1
            elif status == "confirmed":
                confirmed_appointments += 1
            elif status == "cancelled":
                cancelled_appointments += 1
            elif status == "completed":
                completed_appointments += 1
        return jsonify({
            "success": True,
            "stats": {
                "total_patients": total_patients,
                "total_doctors": total_doctors,
                "total_admins": total_admins,
                "total_appointments": total_appointments,
                "pending_appointments": pending_appointments,
                "confirmed_appointments": confirmed_appointments,
                "cancelled_appointments": cancelled_appointments,
                "completed_appointments": completed_appointments
            }
        })
    except Exception as e:
        print(f"Error fetching admin stats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/admin/doctors")
def admin_doctors():
    is_authorized, error_response = check_acl_permission("users", "view_all")
    if not is_authorized:
        return error_response
    try:
        doctors = []
        users = db.collection("users").where("role", "==", "doctor").stream()
        for doc in users:
            user_data = doc.to_dict()
            doctors.append({
                "id": doc.id,
                "custom_id": user_data.get("custom_id", doc.id),
                "name": user_data.get("name", "Unknown"),
                "email": user_data.get("email", "N/A")
            })
        return jsonify({"success": True, "doctors": doctors})
    except Exception as e:
        print(f"Error fetching doctors: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
@app.route("/api/admin/appointments")
def admin_appointments():
    is_authorized, error_response = check_acl_permission("appointments", "view_all")
    if not is_authorized:
        return error_response
    try:
        appointments = []
        docs = db.collection("appointments").stream()
        for doc in docs:
            try:
                d = doc.to_dict()
                aes_key = rsa_decrypt_key(d["encrypted_key"])
                decrypted = aes_decrypt(d["ciphertext"], d["iv"], aes_key)
                patient_uid = decrypted.get("patient_uid")
                if patient_uid:
                    try:
                        patient_doc = db.collection("users").document(patient_uid).get()
                        if patient_doc.exists:
                            patient_data = patient_doc.to_dict()
                            decrypted["patient_name"] = patient_data.get("name", "Unknown")
                            decrypted["patient_custom_id"] = patient_data.get("custom_id", patient_uid)
                        else:
                            decrypted["patient_name"] = "Unknown"
                            decrypted["patient_custom_id"] = decrypted.get("patient_id", "N/A")
                    except:
                        decrypted["patient_name"] = "Unknown"
                        decrypted["patient_custom_id"] = decrypted.get("patient_id", "N/A")
                else:
                    decrypted["patient_name"] = "Unknown"
                    decrypted["patient_custom_id"] = decrypted.get("patient_id", "N/A")
                doctor_uid = decrypted.get("doctor_uid")
                if doctor_uid:
                    try:
                        doctor_doc = db.collection("users").document(doctor_uid).get()
                        if doctor_doc.exists:
                            doctor_data = doctor_doc.to_dict()
                            decrypted["doctor_name"] = doctor_data.get("name", "Unknown")
                            decrypted["doctor_custom_id"] = doctor_data.get("custom_id", doctor_uid)
                        else:
                            decrypted["doctor_name"] = "Unknown"
                            decrypted["doctor_custom_id"] = decrypted.get("doctor_id", "N/A")
                    except:
                        decrypted["doctor_name"] = "Unknown"
                        decrypted["doctor_custom_id"] = decrypted.get("doctor_id", "N/A")
                else:
                    decrypted["doctor_name"] = "Unknown"
                    decrypted["doctor_custom_id"] = decrypted.get("doctor_id", "N/A")
                
                decrypted["id"] = doc.id
                appointments.append(decrypted)
            except Exception as e:
                print(f"Error decrypting appointment {doc.id}: {e}")
                continue
        
        return jsonify({"success": True, "appointments": appointments})
    except Exception as e:
        print(f"Error fetching appointments: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)