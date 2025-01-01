// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract Calculator {

    function add( uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }

    function subtract( uint256 a, uint b ) public pure returns (uint256) {
        return a - b;
    }

    function multiply( uint256 a, uint256 b ) public pure returns (uint256) {
        return a * b;
    }

    function divide( uint256 a, uint b ) public pure returns (uint256) {
        require (b != 0, "Division by zero not allowed");
        return a / b;
    }
    
    function exponent( uint256 a, uint b ) public  pure returns (uint256) {
        return a ** b;
    }

}