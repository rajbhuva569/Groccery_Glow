const express = require("express")
const cors = require("cors")
const mongoose = require("mongoose")
const e = require("express")
const dotenv = require("dotenv").config()
const Stripe = require("stripe");
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
// const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);


const app = express()
app.use(cors())
app.use(express.json({ limit: '10mb' }))
const PORT = process.env.PORT || 8081


//mongodb connection
console.log(process.env.MONGODB_URL);
mongoose.set('strictQuery', false)
mongoose.connect(process.env.MONGODB_URL)
    .then(() => console.log("connect to database"))
    .catch((err) => console.log(err))

// Admin login endpoint
// app.post("/admin/login", async (req, res) => {
//     const { email, password } = req.body;

//     try {
//         if (email === "admin123@gmail.com" && password === "123") {
//             // Authentication successful
//             const admin = { email: "admin123" }; // Creating a basic admin object for session
//             req.session.admin = admin; // Store admin information in session
//             res.json({ success: true, message: 'Login successful' });
//         } else {
//             // Authentication failed
//             res.status(401).json({ success: false, message: 'Invalid email or password' });
//         }
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ success: false, message: 'Internal Server Error' });
//     }
// });
// // Logout endpoint
// app.post("/admin/logout", async (req, res) => {
//     try {
//         // Destroy the session
//         req.session.destroy((err) => {
//             if (err) {
//                 console.error(err);
//                 res.status(500).json({ success: false, message: 'Internal Server Error' });
//             } else {
//                 res.clearCookie('connect.sid'); // Clear the session cookie
//                 res.json({ success: true, message: 'Logout successful' });
//             }
//         });
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ success: false, message: 'Internal Server Error' });
//     }
// });
const adminCredentials = {
    email: 'rajbhuva@gmail.com',
    password: 'admin123'
};

// Login route
app.post('/admin/login', (req, res) => {
    const { email, password } = req.body;


    if (email === adminCredentials.email && password === adminCredentials.password) {
        // Successful login
        res.status(200).json({ success: true });
    } else {
        // Failed login
        res.status(401).json({ success: false, message: 'Invalid email or password' });
    }
});





// schema
const userSchema = mongoose.Schema({
    firstname: String,
    lastname: String,
    email: {
        type: String,
        unique: true
    },
    password: String,
    confirmpassword: String,
    image: String,
    resetToken: String,
    resetTokenExpiry: Date
});

// model
const userModel = mongoose.model("user", userSchema);
//api


app.get('/', (req, res) => {
    res.send("server running")
})
// Add a new API endpoint to retrieve all user data
app.get('/users', async (req, res) => {
    try {
        const users = await userModel.find();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
app.delete('/users/:userId', async (req, res) => {
    const userId = req.params.userId;

    try {
        const deletedUser = await userModel.findByIdAndDelete(userId);

        if (deletedUser) {
            res.status(200).json({ message: "User deleted successfully", alert: true });
        } else {
            res.status(404).json({ message: "User not found", alert: false });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal Server Error", alert: false });
    }
});

app.post('/login/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await userModel.findOne({ email });

        if (user) {
            const resetToken = crypto.randomBytes(20).toString('hex');
            user.resetToken = resetToken;
            user.resetTokenExpiry = Date.now() + 3600000;
            await user.save();
            res.json({ token: resetToken });
        } else {
            res.status(404).json({ message: 'User not found.' });
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// resetting password
app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        const user = await userModel.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });

        if (user) {
            user.password = newPassword;
            user.resetToken = undefined;
            user.resetTokenExpiry = undefined;
            await user.save();
            res.status(200).json({ message: 'Password reset successfully.' });
        } else {
            res.status(400).json({ message: 'Invalid or expired reset token.' });
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});










// app.post('/signup', async (req, res) => {
//     console.log(req.body);
//     const { email } = req.body

//     const user = await userModel.findOne({ email: email }).exec()

//     if (user) {
//         res.send({ message: "email id already register" })
//     } else {

//         const data = new userModel(req.body)
//         console.log("Data to be saved:", data); // Add this line for debugging
//         const save = await data.save()
//         console.log("Save result:", save); // Add this line for debugging
//         res.send({ message: "successful signup" })
//     }
// })
// app.post('/signup', async (req, res) => {
//     console.log(req.body);
//     const { email } = req.body;

//     const user = await userModel.findOne({ email }).exec();

//     if (user) {
//         res.status(400).json({ message: "Email already registered", alert: false });
//     } else {
//         const data = new userModel(req.body);
//         console.log("Data to be saved:", data);
//         const save = await data.save();
//         console.log("Save result:", save);
//         res.status(201).json({ message: "Successful signup", alert: true });
//     }
// });

app.post('/signup', async (req, res) => {
    try {
        const { firstname, lastname, email, password, confirmpassword, image } = req.body;

        // Validate input fields
        if (!(firstname && lastname && email && password && confirmpassword)) {
            throw new Error('Please enter all required fields');
        }

        // Validate password and confirm password
        if (password !== confirmpassword) {
            throw new Error('Password and confirm password do not match');
        }

        // Check if the email is already registered
        const existingUser = await userModel.findOne({ email }).exec();
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered', alert: false });
        }

        // Create a new user
        const newUser = new userModel({
            firstname,
            lastname,
            email,
            password,
            confirmpassword,
            image
        });

        // Save the new user to the database
        const savedUser = await newUser.save();

        res.status(201).json({ message: 'Successful signup', alert: true });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Signup failed. Please try again.', alert: false });
    }
});
//api login
// app.post("./login", (req, res) => {
//     console.log(req.body)
//     const { email } = req.body
//     userModel.findOne({ email: email }), (err, result) => {

//         if (result) {
//             console.log(result);
//             const dataSend = {
//                 _id: result.id,
//                 firstname: result.firstname,
//                 lastname: result.lastname,
//                 email: result.email,
//                 password: result.password,
//                 image: result.image,
//             }
//             console.log(dataSend);
//             res.status(201)({ message: "login is succesfully", alert: true });
//         }

//     }
// })
// app.post("/login", async (req, res) => {
//     console.log(req.body);
//     const { email } = req.body;

//     try {
//         const user = await userModel.findOne({ email: email });

//         if (user) {
//             console.log(user);
//             const dataSend = {
//                 _id: user.id,
//                 firstname: user.firstname,
//                 lastname: user.lastname,
//                 email: user.email,
//                 password: user.password,
//                 image: user.image,
//             };
//             console.log(dataSend);
//             res.status(201).json({ message: "Login is successful", alert: true, data: dataSend });
//         } else {
//             res.status(401).json({ message: "Invalid email or password", alert: false });
//         }
//     } catch (err) {
//         console.error(err);
//         res.status(500).json({ message: "Internal Server Error", alert: false });
//     }
// });
app.post("/login", async (req, res) => {
    console.log(req.body);
    const { email, password } = req.body;

    try {
        const user = await userModel.findOne({ email: email });

        if (user) {
            // Check if the password matches
            if (user.password === password) {
                // Password matches, allow login
                const dataSend = {
                    _id: user.id,
                    firstname: user.firstname,
                    lastname: user.lastname,
                    email: user.email,
                    password: user.password,
                    image: user.image,
                };
                res.status(201).json({ message: "Login is successful", alert: true, data: dataSend });
            } else {
                // Password doesn't match, send error message
                res.status(401).json({ message: "Invalid email or password", alert: false });
            }
        } else {
            // User not found, send error message
            res.status(401).json({ message: "Invalid email or password", alert: false });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal Server Error", alert: false });
    }
});


///*****payment getWay */
console.log(process.env.STRIPE_SECRET_KEY)
// const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// app.post("/create-checkout-session", async (req, res) => {
//     console.log(req.body);
//     try {
//         const lineItems = req.body.map((item) => {
//             return {
//                 price_data: {
//                     currency: "inr",
//                     product_data: {
//                         name: item.name,
//                     },
//                     unit_amount: item.price * 100,
//                 },
//                 adjustable_quantity: {
//                     enabled: true,
//                     minimum: 1,
//                 },
//                 quantity: item.qty,
//             };
//         });

//         // Creating a customer with details
//         const customer = await stripe.customers.create({
//             name: req.body.shipping_name,
//             address: {
//                 line1: req.body.shipping_address_line1,
//                 city: req.body.shipping_address_city,
//                 postal_code: req.body.shipping_address_postal_code,
//                 state: req.body.shipping_address_state, // Include state if available
//                 country: req.body.shipping_address_country,
//             },
//             phone: req.body.phone,
//             email: req.body.email,
//         });

//         console.log("Customer created:", customer);

//         const session = await stripe.checkout.sessions.create({
//             payment_method_types: ["card"],
//             billing_address_collection: "auto",
//             shipping_address_collection: {
//                 allowed_countries: ["IN"],
//             },

//             line_items: lineItems,
//             mode: "payment",
//             customer: customer.id,
//             success_url: `${process.env.FRONTEND_URL}/success`,
//             cancel_url: `${process.env.FRONTEND_URL}/cancel`,
//         });

//         res.status(200).json(session.id);
//     }
//     catch (err) {
//         console.error(err);
//         res.status(err.statusCode || 500).json(err.message);
//     }
// });
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

app.post("/create-checkout-session", async (req, res) => {
    console.log(req.body);
    try {
        const orderId = uuidv4();
        const lineItems = req.body.map((item) => {
            return {
                price_data: {
                    currency: "inr",
                    product_data: {
                        name: item.name,
                    },
                    unit_amount: item.price * 100,
                },
                adjustable_quantity: {
                    enabled: true,
                    minimum: 1,
                },
                quantity: item.qty,
            };
        });

        // Check if the transaction is in a currency other than INR
        const currency = req.body.currency || 'inr';

        // Creating a customer with details
        const customer = await stripe.customers.create({
            name: req.body.shipping_name, // Assuming you have shipping_name in your request body
            address: {
                // If the currency is not INR, set the country outside India
                country: currency === 'inr' ? 'IN' : 'US', // Change 'US' to the appropriate country code
                // Include other address details as needed
                line1: req.body.shipping_address_line1,
                city: req.body.shipping_address_city,
                postal_code: req.body.shipping_address_postal_code,
            },
            phone: req.body.phone, // Add phone if available in your request body
            email: req.body.email, // Add email if available in your request body
        });
        console.log("Customer created:", customer);

        // Assuming you have an Order model defined
        const order = new Order({
            userId: req.body.userId,
            products: req.body.map(item => ({ productId: item.productId, quantity: item.qty })),
            totalPrice: req.body.reduce((total, item) => total + (item.price * item.qty), 0),
            orderDate: new Date(), // Capture the current date/time
            status: "pending", // Set initial order status
            shippingInfo: {
                address: req.body.shipping_address_line1,
                city: req.body.shipping_address_city,
                postal_code: req.body.shipping_address_postal_code,
                country: req.body.shipping_address_country // Add country if available
                // Add other shipping information as needed
            }
        })

        // Save the order to the database
        await order.save();

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            billing_address_collection: "auto",
            shipping_address_collection: {
                // If the currency is not INR, disallow shipping to India
                allowed_countries: currency === 'inr' ? ["IN"] : [],
            },
            // Your other parameters...
            line_items: lineItems,
            mode: "payment",
            customer: customer.id,
            // Your other parameters...
            success_url: `${process.env.FRONTEND_URL}/success`,
            cancel_url: `${process.env.FRONTEND_URL}/cancel`,
        });
        console.log("Payment details:", {
            sessionId: session.id,
            customer: customer,
            lineItems: lineItems,
            currency: currency
            // Add more details as needed
        });

        res.status(200).json({ session: session.id, orderId: orderId });
        // res.status(200).json(orderId);
    } catch (err) {
        console.error(err);
        res.status(err.statusCode || 500).json(err.message);
    }
});

// Define Order Schema
const orderSchema = mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user' // Reference to the User model
    },
    products: [{
        productId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'product' // Reference to the Product model
        },
        quantity: Number
    }],
    totalPrice: Number,
    orderDate: {
        type: Date,
        default: Date.now
    }, status: String, // Order status field
    shippingInfo: { // Shipping information object
        address: String,
        city: String,
        postal_code: String,
        country: String // Add country if available
        // Add other shipping information fields as needed
    }
});

// Create Order model
const Order = mongoose.model('order', orderSchema);

// Create API Endpoints
// Endpoint to create a new order
app.post('/orders', async (req, res) => {
    try {
        const { userId, products, totalPrice } = req.body;
        const newOrder = new Order({ userId, products, totalPrice });
        const savedOrder = await newOrder.save();
        res.status(201).json(savedOrder);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Endpoint to retrieve all orders
app.get('/orders', async (req, res) => {
    try {
        const orders = await Order.find();
        res.json(orders);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Endpoint to retrieve a specific order by ID
app.get('/orders/:orderId', async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ message: 'Order not found' });
        }
        res.json(order);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Endpoint to update a specific order by ID
app.put('/orders/:orderId', async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const updatedOrder = await Order.findByIdAndUpdate(orderId, req.body, { new: true });
        if (!updatedOrder) {
            return res.status(404).json({ message: 'Order not found' });
        }
        res.json(updatedOrder);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});
app.put("/orders/:orderId/status", async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const { status } = req.body;

        // Find the order by orderId and update its status
        await Order.findByIdAndUpdate(orderId, { status: status });

        res.status(200).json({ message: "Order status updated successfully" });
    } catch (err) {
        console.error(err);
        res.status(err.statusCode || 500).json(err.message);
    }
});


// Endpoint to delete a specific order by ID
app.delete('/orders/:orderId', async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const deletedOrder = await Order.findByIdAndDelete(orderId);
        if (!deletedOrder) {
            return res.status(404).json({ message: 'Order not found' });
        }
        res.json({ message: 'Order deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


// app.post("/stripe-webhook", async (req, res) => {
//     const payload = req.body;
//     const sig = req.headers["stripe-signature"];

//     let event;

//     try {
//         // Verify webhook signature
//         event = stripe.webhooks.constructEvent(payload, sig, process.env.STRIPE_WEBHOOK_SECRET);
//     } catch (err) {
//         // Return error response if signature is invalid
//         return res.status(400).send(`Webhook Error: ${err.message}`);
//     }

//     // Handle specific webhook event types
//     switch (event.type) {
//         case 'payment_intent.succeeded':
//             // Handle successful payment intent
//             handlePaymentIntentSucceeded(event);
//             break;
//         case 'payment_intent.payment_failed':
//             // Handle failed payment intent
//             handlePaymentIntentFailed(event);
//             break;
//         // Add more event handlers as needed
//         default:
//             // For unrecognized event types, return success response
//             res.status(200).end();
//     }
// });

// Function to handle successful payment intent event
function handlePaymentIntentSucceeded(event) {
    const paymentIntent = event.data.object;
    // Add your logic to handle successful payment intent here
    console.log("Payment Intent Succeeded:", paymentIntent.id);
}

// Function to handle failed payment intent event
function handlePaymentIntentFailed(event) {
    const paymentIntent = event.data.object;
    // Add your logic to handle failed payment intent here
    console.log("Payment Intent Failed:", paymentIntent.id);
}
// Function to calculate the total amount based on the items in the request
function calculateTotalAmount(items) {
    return items.reduce((total, item) => {
        return total + item.price * item.qty;
    }, 0) * 100; // Convert the total amount to cents
}




// app.post("/create-checkout-session", async (req, res) => {
//     const stripe = new Stripe(process.env.STRIPE_SECRET_KEY)

//     try {
//         const params = {
//             submit_type: 'pay',
//             mode: "payment",
//             payment_method_types: ['card'],
//             billing_address_collection: "auto",
//             shipping_options: [{ shipping_rate: "shr_1Oo5mGSHVXtnbcsHF87QRqwz" }],

//             line_items: req.body.map((item) => {
//                 return {
//                     price_data: {
//                         currency: "inr",
//                         product_data: {
//                             name: item.name,
//                             // images : [item.image]
//                         },
//                         unit_amount: item.price * 100,
//                     },
//                     adjustable_quantity: {
//                         enabled: true,
//                         minimum: 1,
//                     },
//                     quantity: item.qty
//                 }
//             }),

//             success_url: `${process.env.FRONTEND_URL}/success`,
//             cancel_url: `${process.env.FRONTEND_URL}/cancel`,

//         }


//         const session = await stripe.checkout.sessions.create(params)
//         // console.log(session)
//         res.status(200).json(session.id)
//     }
//     catch (err) {
//         res.status(err.statusCode || 500).json(err.message)
//     }

// })

// const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// app.post("/create-checkout-session", async (req, res) => {
//     try {
//         const params = {
//             submit_type: 'pay',
//             mode: "payment",
//             payment_method_types: ['card'],
//             billing_address_collection: "auto",
//             shipping_options: [{ shipping_rate: "shr_1Oo5mGSHVXtnbcsHF87QRqwz" }],

//             line_items: req.body.map((item) => {
//                 return {
//                     price_data: {
//                         currency: "inr",
//                         product_data: {
//                             name: item.name,
//                             // images : [item.image]
//                         },
//                         unit_amount: item.price * 100,
//                     },
//                     adjustable_quantity: {
//                         enabled: true,
//                         minimum: 1,
//                     },
//                     quantity: item.qty
//                 }
//             }),

//             success_url: `${process.env.FRONTEND_URL}/success`,
//             cancel_url: `${process.env.FRONTEND_URL}/cancel`,
//         };

//         // Create a PaymentIntent to handle the payment on the server side
//         const paymentIntent = await stripe.paymentIntents.create({
//             amount: calculateTotalAmount(req.body), // Use a function to calculate the total amount based on your items
//             currency: "inr", // Use the appropriate currency for India
//             payment_method: 'pm_card_visa', // Use the appropriate payment method
//             billing_details: {
//                 name: req.body[0].billing_name, // Assuming billing_name is available in your request
//                 address: {
//                     line1: req.body[0].billing_address, // Assuming billing_address is available in your request
//                     city: req.body[0].billing_city, // Assuming billing_city is available in your request
//                     postal_code: req.body[0].billing_postal_code, // Assuming billing_postal_code is available in your request
//                     country: 'IN', // Use the appropriate country code for India
//                 },
//             },
//         });

//         // Add the payment_intent parameter to the params object
//         params.payment_intent = paymentIntent.id;

//         const session = await stripe.checkout.sessions.create(params);
//         res.status(200).json(session.id);
//     } catch (err) {
//         res.status(err.statusCode || 500).json(err.message);
//     }
// });


//product section

const schemaProduct = mongoose.Schema({

    name: String,
    category: String,
    image: String,
    price: String,
    description: String
})
const productModal = mongoose.model("product", schemaProduct)


//save product in data
//api
app.post("/uploadProduct", async (req, res) => {
    console.log(req.body);
    const data = await productModal(req.body)
    const datasave = await data.save()
    res.send({ message: "uploaded succesfully" })
})

app.get("/products", async (req, res) => {
    const data = await productModal.find({})
    res.send(JSON.stringify(data))
    // res.send("data")
})
app.delete('/removeProduct/:id', async (req, res) => {
    try {
        const removedProduct = await productModal.findByIdAndDelete(req.params.id);
        res.send({ message: 'Product removed successfully', data: removedProduct });
    } catch (error) {
        res.status(500).send({ message: 'Error removing product', error: error.message });
    }
});


// Update product
// app.get('/editproduct/:id', async (req, res) => {
//     try {
//         const product = await productModal.findById(req.params.id);
//         if (!product) {
//             return res.status(404).send({ message: 'Product not found' });
//         }
//         res.send(product);
//     } catch (error) {
//         res.status(500).send({ message: 'Error fetching product', error: error.message });
//     }
// });
app.get('/editproduct/:id', async (req, res) => {
    try {
        const product = await productModal.findById(req.params.id).populate('category');
        if (!product) {
            return res.status(404).send({ message: 'Product not found' });
        }
        res.send(product);
    } catch (error) {
        res.status(500).send({ message: 'Error fetching product', error: error.message });
    }
});

app.put('/editproduct/:id', async (req, res) => {
    try {
        const updatedProduct = await productModal.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );

        console.log("Updated Product:", updatedProduct);

        if (!updatedProduct) {
            return res.status(404).send({ message: 'Product not found' });
        }

        res.send({ message: 'Product updated successfully', data: updatedProduct });

    } catch (error) {
        res.status(500).send({ message: 'Error updating product', error: error.message });
    }
});
// const categorySchema = mongoose.Schema({
//     name: String
// });

// const Category = mongoose.model('Category', categorySchema);

// module.exports = Category;
// app.get("/category", async (req, res) => {
//     try {
//         const categories = await productModal.distinct("category");
//         res.json(categories);
//     } catch (error) {
//         res.status(500).json({ error: 'Internal Server Error' });
//     }
// });
// // Endpoint to add a new category
// app.post('/category', async (req, res) => {
//     try {
//         const { name } = req.body;
//         // Check if category name is provided
//         if (!name) {
//             return res.status(400).json({ success: false, message: "Category name is required" });
//         }

//         // Check if category already exists
//         const existingCategory = await Category.findOne({ name });
//         if (existingCategory) {
//             return res.status(400).json({ success: false, message: "Category already exists" });
//         }

//         // Create new category
//         const newCategory = new Category({ name });
//         await newCategory.save();

//         // Send response
//         res.status(201).json({ success: true, message: "Category added successfully", category: newCategory.name });
//     } catch (error) {
//         console.error('Error adding category:', error);
//         res.status(500).json({ success: false, message: "Internal Server Error" });
//     }
// });

// // Endpoint to get all categories
// app.get('/category', async (req, res) => {
//     try {
//         const categories = await Category.find({}, 'name'); // Retrieve only category names
//         res.json(categories.map(category => category.name)); // Send array of category names
//     } catch (error) {
//         console.error('Error fetching categories:', error);
//         res.status(500).json({ success: false, message: "Internal Server Error" });
//     }
// });



app.get('/payments', async (req, res) => {
    try {
        const payments = await stripe.paymentIntents.list();
        res.json(payments.data);
        console.log(payments.data);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
const categorySchema = new mongoose.Schema({
    name: String
});
const Category = mongoose.model('Category', categorySchema);

// Route to get all categories
app.get('/categories', async (req, res) => {
    try {
        const categories = await Category.find();
        res.json(categories);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route to get a single category by ID
app.get('/categories/:id', async (req, res) => {
    const id = req.params.id;
    try {
        const category = await Category.findById(id);
        if (category) {
            res.json(category);
        } else {
            res.status(404).json({ error: 'Category not found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route to add a new category
app.post('/categories', async (req, res) => {
    const { name } = req.body;
    try {
        const newCategory = new Category({ name });
        const savedCategory = await newCategory.save(); // Save the new category to the database
        res.status(201).json({ message: 'Category created successfully', category: savedCategory }); // Send response with newly created category
    } catch (error) {
        res.status(400).json({ error: 'Failed to create category' });
    }
});

// Route to update a category
app.put('/categories/:id', async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;

    try {
        const updatedCategory = await Category.findByIdAndUpdate(id, { name }, { new: true });

        if (!updatedCategory) {
            return res.status(404).json({ message: 'Category not found' });
        }

        res.json({ category: updatedCategory });
    } catch (error) {
        console.error('Error updating category:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// Route to delete a category
app.delete('/categories/:id', async (req, res) => {
    const id = req.params.id;
    try {
        await Category.findByIdAndDelete(id);
        res.json({ message: 'Category deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
const contactSchema = new mongoose.Schema({
    name: String,
    email: String,
    subject: String,
    message: String
});

// Create a model based on the schema
const Contact = mongoose.model('Contact', contactSchema);

// Endpoint to handle form submissions
app.get('/contact', async (req, res) => {
    try {
        // Fetch all contact submissions from the database
        const submissions = await Contact.find();

        // Send the contact submissions data as a response
        res.status(200).json(submissions);
    } catch (error) {
        console.error('Error:', error);
        // Respond with error message
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post('/contact', async (req, res) => {
    try {
        // Extract form data from request body
        const { name, email, subject, message } = req.body;

        // Create a new contact record
        const newContact = new Contact({
            name,
            email,
            subject,
            message
        });

        // Save the contact record to the database
        await newContact.save();

        // Respond with success message
        res.status(201).json({ message: 'Form submitted successfully' });
    } catch (error) {
        console.error('Error:', error);
        // Respond with error message
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


app.listen(PORT, () => console.log("server is running" + PORT))
