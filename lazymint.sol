// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

// import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
// import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// import "@openzeppelin/contracts/utils/Counters.sol";

contract LazyNFT is AccessControl {
    // bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // using Counters for Counters.Counter;
    // Counters.Counter private _tokenIds;
    constructor() {}

    // constructor(address minter)
    //   // ERC721("LazyNFT", "LAZ") {
    //   //   _setupRole(MINTER_ROLE, minter);
    //   }

    struct NFTVoucher {
        uint256 tokenId;
        uint256 minPrice;
        string uri;
    }

    // function redeem(address redeemer, NFTVoucher calldata voucher, bytes memory signature) public payable {
    //   address signer = _verify(voucher, signature);
    //   require(hasRole(MINTER_ROLE, signer), "Invalid signature - unknown signer");
    //   mintItem(signer);
    //   // minting logic...
    // }

    // function _verify(NFTVoucher voucher, bytes memory signature) private returns (address memory signer) {
    //   // verify signature against input and recover address, or revert transaction if signature is invalid
    //   _verify()
    // }

    // function mintItem(address minter) public returns(uint){
    //       _tokenIds.increment();
    //       uint newItemId =  _tokenIds.current();
    //       _mint(minter, newItemId);
    //       // _setTokenURI(newItemId, tokenURI);
    //       return newItemId;
    //   }

    function test() public view returns (uint256) {
        if (
            _verify(
                "Very Message Such Wow",
                "0xa9165f66c44514bdcdd3760c6c93e5f13dbac11d90954d183bb44f5e89bbd3290f7ae3dcf41139ff4117ee2ccfa5744dab112c79c824815979064e2d619e0e4d1b",
                0x89271A265B8b8aDF16BA58E64fbF333f2E95158b
            )
        ) {
            return 1;
        } else {
            return 0;
        }
    }

    using ECDSA for bytes32;

    function _verify(
        bytes32 data,
        bytes memory signature,
        address account
    ) internal pure returns (bool) {
        bytes32 signedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", data)
        );
        return signedHash.recover(signature) == account;
        // return data
        //     .toEthSignedMessageHash()
        //     .recover(signature) == account;
    }

    function _Tverify(
        bytes32 data,
        bytes memory signature,
        address account
    ) public view returns (address) {
        // bytes32 signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", data));
        // return signedHash;
        return data.recover(signature);
        // return data
        //     .toEthSignedMessageHash()
        //     .recover(signature) == account;
    }

    // function _Averify(bytes memory data, bytes memory signature) public view returns (address) {
    //   // bytes32 signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", data));
    //   // return signedHash;
    //   // return data.recover(signature);
    //   return data
    //       .toEthSignedMessageHash()
    //       .recover(signature);
    //   // return data.toEthSignedMessageHash().recover(signature);

    //   // return keccak256(data).toEthSignedMessageHash().recover(signature);
    // }

    function _bverify(bytes32 data, bytes memory signature)
        public
        view
        returns (address)
    {
        return data.toEthSignedMessageHash().recover(signature);
    }

    function stringToBytes32(string memory source)
        public
        pure
        returns (bytes32 result)
    {
        bytes memory tempEmptyStringTest = bytes(source);
        if (tempEmptyStringTest.length == 0) {
            return 0x0;
        }

        assembly {
            result := mload(add(source, 32))
        }
    }

    function prefixed(bytes32 hash) public view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            );
    }
}
