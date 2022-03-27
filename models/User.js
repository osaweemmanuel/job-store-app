import mongoose from 'mongoose'
import validator from 'validator'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const UserSchema=new mongoose.Schema({

    name:{
            type:String,
            required:[true,'please provide name'],
            minlength:5,
            maxlength:20,
            trim:true,
        },

        email:{
            type:String,
            required:[true,'please provide email'],
            validate: {
                validator: validator.isEmail,
                message:'please provide a valid email',
            },
            unique:true,
           
        },


        password:{
            type:String,
            required:[true,'please provide email'],
            minlength:6,
            select:false,
        },


        lastName:{
            type:String,
            maxlength:20,
            default: 'osawe',
           
        },

        location:{
            type:String,
            trim:true,
            maxlength:20,
            default: 'Nigeria',
           
        },

})


//hashing password
UserSchema.pre('save',async function(){
    //console.log(this.modifiedPaths())
    if(!this.isModified('password')) return
    const salt=await bcrypt.genSalt(10)
    this.password=await bcrypt.hash(this.password,salt)
})

//creating jsonwebtoken
UserSchema.methods.createJWT=function(){
    return jwt.sign({userId: this._id},process.env.JWT_SECRET,{expiresIn :process.env.JWT_LIFETIME})
}


//compare password

UserSchema.methods.comparePassword= async function(candidatePassword){
    const isMatch= await bcrypt.compare(candidatePassword,this.password)
    return isMatch

}




export default mongoose.model('User',UserSchema)