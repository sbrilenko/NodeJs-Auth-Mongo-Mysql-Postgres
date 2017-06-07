"use strict";
var bcrypt   = require('bcrypt-nodejs');

module.exports = function(sequelize, DataTypes) {
    return sequelize.define('User', {
    id: {
      autoIncrement: true,
      primaryKey: true,
      type: DataTypes.INTEGER
    },
    localname: {
      type: DataTypes.STRING,
      allowNull: true,
      unique: 'compositeIndex'
    },
    localemail: {
      type: DataTypes.STRING,
      allowNull: true,
      validate: { isEmail: true },
      unique: true
    },
    localpass: {
      type: DataTypes.STRING,
      allowNull: true
    },
    facebookid: {
      type: DataTypes.STRING,
      allowNull: true,
      unique: true
    },
    facebooktoken: {
      type: DataTypes.STRING,
      allowNull: true,
      unique: true
    },
    facebookemail: {
      type: DataTypes.STRING,
      allowNull: true,
      validate: { isEmail: true },
      unique: true
    },
    facebookname: {
      type: DataTypes.STRING,
      allowNull: true
    },
    facebookusername: {
      type: DataTypes.STRING,
      allowNull: true
    },
    twitterid: {
      type: DataTypes.STRING,
      allowNull: true,
      unique: true
    },
    twittertoken: {
      type: DataTypes.STRING,
      allowNull: true,
      unique: true
    },
    twitterdisplayname: {
      type: DataTypes.STRING,
      allowNull: true
    },
    twitterusername: {
      type: DataTypes.STRING,
      allowNull: true
    },
    googleid: {
      type: DataTypes.STRING,
      allowNull: true,
      unique: true
    },
    googletoken: {
      type: DataTypes.STRING,
      allowNull: true,
      unique: true
    },
    googleemail: {
      type: DataTypes.STRING,
      allowNull: true,
      validate: { isEmail: true },
      unique: true
    },
    googlename: {
      type: DataTypes.STRING,
      allowNull: true
    }
  }, {
    freezeTableName: true,
    classMethods: {
      generateHash: function(password) {
        return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
      },
      validPassword: function(password) {
        return bcrypt.compareSync(password, this.password);
      }
    },
    instanceMethods: {
        validPassword: function(password) {
            return bcrypt.compareSync(password, this.password);
        }
    },
    getterMethods   : {
    },
    setterMethods   : {
      // address: function(value) {
      //   var names = value.split(', ');
      //   this.setDataValue('country', names[0]);
      //   this.setDataValue('state', names[1]);
      // },
    }
  });
};