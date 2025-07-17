const mongoose = require('mongoose');

const resetCodeSchema = new mongoose.Schema({
    userId : {type:String, required:true},
    code : {type:String, required:true},
    duration : {type:Date, required:true},
});

module.exports = mongoose.model('ResetCodes',resetCodeSchema);