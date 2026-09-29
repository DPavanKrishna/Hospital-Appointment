document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("bookingForm");

    // Select time slot dynamically
    const timeSlots = document.querySelectorAll(".time-slot");
    const timeInput = document.getElementById("time");
    timeSlots.forEach(slot => {
        slot.addEventListener("click", () => {
            timeInput.value = slot.dataset.time;
            timeSlots.forEach(s => s.classList.remove("selected"));
            slot.classList.add("selected");
        });
    });

    form.addEventListener("submit", async (e) => {
        e.preventDefault(); // prevent full page reload

        const formData = {
            patient_id: "{{ session.patient_id }}", // from Flask session
            doctor: form.doctor.value,
            date: form.date.value,
            time: form.time.value,
            reason: form.reason.value,
            notes: form.notes.value,
            status: "pending"
        };

        try {
            const res = await fetch("/book-appointment", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(formData)
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const result = await res.json();

            if (result.success) {
                alert("Appointment booked successfully!");

                // Optional: clear form
                form.reset();

                // Update patient dashboard table immediately
                if (window.opener) {
                    window.opener.loadAppointments();
                } else {
                    loadAppointments(); // if same page
                }
            } else {
                alert("Failed to book appointment: " + result.error);
            }

        } catch (err) {
            console.error(err);
            alert("Error booking appointment");
        }
    });
});
