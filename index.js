require("dotenv").config({ override: true });

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const dns = require("dns");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const {
    MongoClient,
    ServerApiVersion,
    ObjectId
} = require("mongodb");


dns.setServers([
    "8.8.8.8",
    "1.1.1.1"
]);


const app = express();
const port = process.env.PORT || 5000;


// middleware

app.use(cors({
    origin:[
        process.env.CLIENT_URL,
        "http://localhost:3000"
    ],
    credentials:true
}));

app.use(express.json());
app.use(cookieParser());



// MongoDB

const client = new MongoClient(
    process.env.MONGODB_URI,
    {
        serverApi:{
            version:ServerApiVersion.v1,
            strict:true,
            deprecationErrors:true
        }
    }
);


const db = client.db("ticketbari");

const usersCollection = db.collection("users");
const ticketsCollection = db.collection("tickets");
const bookingsCollection = db.collection("bookings");




// JWT verify

const verifyJWT = (req,res,next)=>{


    const token =
    req.headers.authorization?.split(" ")[1];


    if(!token){

        return res.status(401)
        .send({
            message:"Unauthorized"
        });

    }


    jwt.verify(
        token,
        process.env.JWT_SECRET,
        (err,decoded)=>{


            if(err){

                return res.status(401)
                .send({
                    message:"Unauthorized"
                });

            }


            req.decoded = decoded;

            next();


        }
    );


};





// Admin verify


const verifyAdmin = async(req,res,next)=>{


    const email = req.decoded.email;


    const user =
    await usersCollection.findOne({
        email
    });


    if(user?.role !== "admin"){

        return res.status(403)
        .send({
            message:"Forbidden"
        });

    }


    next();


};




// Vendor verify


const verifyVendor = async(req,res,next)=>{


    const email=req.decoded.email;


    const user =
    await usersCollection.findOne({
        email
    });



    if(
        user?.role !== "vendor" &&
        user?.role !== "admin"
    ){

        return res.status(403)
        .send({
            message:"Forbidden"
        });

    }


    next();


};





// JWT create


app.post("/jwt",(req,res)=>{


    const user=req.body;


    const token =
    jwt.sign(
        user,
        process.env.JWT_SECRET,
        {
            expiresIn:"7d"
        }
    );


    res.send({
        token
    });


});






// Save user


app.post("/users/save",async(req,res)=>{


    const user=req.body;


    const exists =
    await usersCollection.findOne({
        email:user.email
    });



    if(exists){

        return res.send({
            message:"User exists"
        });

    }



    const newUser={

        name:user.name,

        email:user.email,

        photoURL:user.photoURL || "",

        role:"user",

        createdAt:new Date()

    };



    const result =
    await usersCollection.insertOne(newUser);



    res.send(result);


});






// Get user


app.get(
"/users/email/:email",
verifyJWT,
async(req,res)=>{


    const email=req.params.email;


    const result =
    await usersCollection.findOne({
        email
    });


    res.send(result);


});






// All users admin


app.get(
"/users",
verifyJWT,
verifyAdmin,
async(req,res)=>{


    const result =
    await usersCollection.find()
    .toArray();


    res.send(result);


});






// Change role


app.patch(
"/users/role/:id",
verifyJWT,
verifyAdmin,
async(req,res)=>{


const id=req.params.id;

const {role}=req.body;



const result =
await usersCollection.updateOne(

{
_id:new ObjectId(id)
},

{
$set:{
role
}
}

);



res.send(result);



});









// Create ticket vendor


app.post(
"/tickets",
verifyJWT,
verifyVendor,
async(req,res)=>{


const ticket=req.body;


ticket.createdAt=new Date();


const result =
await ticketsCollection.insertOne(ticket);


res.send(result);


});








// Get tickets


app.get(
"/tickets",
async(req,res)=>{


const result =
await ticketsCollection
.find()
.toArray();



res.send(result);


});









// Single ticket


app.get(
"/tickets/:id",
async(req,res)=>{


const id=req.params.id;


const result =
await ticketsCollection.findOne({

_id:new ObjectId(id)

});



res.send(result);



});









// Booking create


app.post(
"/bookings",
verifyJWT,
async(req,res)=>{


const booking=req.body;


booking.email=req.decoded.email;

booking.status="pending";

booking.createdAt=new Date();



const result =
await bookingsCollection.insertOne(
booking
);



res.send(result);



});








// User bookings


app.get(
"/my-bookings",
verifyJWT,
async(req,res)=>{


const email=req.decoded.email;



const result =
await bookingsCollection
.find({
email
})
.toArray();



res.send(result);



});









// Stripe payment


app.post(
"/create-payment-intent",
verifyJWT,
async(req,res)=>{


const {price}=req.body;



const amount =
parseInt(price * 100);



const paymentIntent =
await stripe.paymentIntents.create({

amount,

currency:"usd",

payment_method_types:[
"card"
]

});



res.send({

clientSecret:
paymentIntent.client_secret

});


});









// update payment


app.patch(
"/bookings/payment/:id",
verifyJWT,
async(req,res)=>{


const id=req.params.id;



const result =
await bookingsCollection.updateOne(

{
_id:new ObjectId(id)
},

{
$set:{
status:"paid"
}
}

);



res.send(result);


});










app.get("/",(req,res)=>{


res.send(
"Ticket Bari Server Running"
);


});








async function run(){


try{


await client.connect();


await db.command({
ping:1
});


console.log(
"MongoDB Connected"
);



}
catch(error){

console.log(error);

}


}


run();







app.listen(port,()=>{


console.log(
`Server running ${port}`
);


});