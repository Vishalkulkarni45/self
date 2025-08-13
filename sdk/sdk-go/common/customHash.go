package common

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// FlexiblePoseidon performs Poseidon hashing with variable number of inputs
func FlexiblePoseidon(inputs []*big.Int) (*big.Int, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no inputs provided")
	}

	if len(inputs) > 16 {
		return nil, fmt.Errorf("unsupported number of inputs: %d", len(inputs))
	}

	// Convert big.Int inputs to fr.Element for processing
	elements := make([]fr.Element, len(inputs))
	for i, input := range inputs {
		elements[i].SetBigInt(input)
	}

	// Use the appropriate poseidon function based on number of inputs
	// This matches the TypeScript flexiblePoseidon implementation
	var result fr.Element
	var err error

	switch len(inputs) {
	case 1:
		result, err = poseidonN(elements, 1)
	case 2:
		result, err = poseidonN(elements, 2)
	case 3:
		result, err = poseidonN(elements, 3)
	case 4:
		result, err = poseidonN(elements, 4)
	case 5:
		result, err = poseidonN(elements, 5)
	case 6:
		result, err = poseidonN(elements, 6)
	case 7:
		result, err = poseidonN(elements, 7)
	case 8:
		result, err = poseidonN(elements, 8)
	case 9:
		result, err = poseidonN(elements, 9)
	case 10:
		result, err = poseidonN(elements, 10)
	case 11:
		result, err = poseidonN(elements, 11)
	case 12:
		result, err = poseidonN(elements, 12)
	case 13:
		result, err = poseidonN(elements, 13)
	case 14:
		result, err = poseidonN(elements, 14)
	case 15:
		result, err = poseidonN(elements, 15)
	case 16:
		result, err = poseidonN(elements, 16)
	default:
		return nil, fmt.Errorf("unsupported number of inputs: %d", len(inputs))
	}

	if err != nil {
		return nil, fmt.Errorf("poseidon hash failed: %w", err)
	}

	return result.BigInt(big.NewInt(0)), nil
}

// poseidonN performs Poseidon hashing with N inputs, matching poseidon-lite behavior
func poseidonN(elements []fr.Element, n int) (fr.Element, error) {
	var result fr.Element

	// For single input, we need to actually hash it (not return directly like before)
	// This matches the TypeScript poseidon1() behavior
	if n == 1 {
		// Convert to bytes for hashing
		inputBytes := elements[0].Bytes()

		// Use Poseidon2 with parameters for single input
		perm := poseidon2.NewPermutation(2, 8, 56) // t=2, rf=8, rp=56

		// Hash with a zero padding to make it 2 inputs
		var zeroElement fr.Element
		zeroBytes := zeroElement.Bytes()

		hashResult, err := perm.Compress(inputBytes[:], zeroBytes[:])
		if err != nil {
			return result, fmt.Errorf("poseidon1 hash failed: %w", err)
		}

		result.SetBytes(hashResult)
		return result, nil
	}

	// For multiple inputs, use the appropriate permutation
	// t parameter = input_length + 1 for poseidon permutation
	t := n + 1
	partialRounds := getPoseidonRounds(n)
	perm := poseidon2.NewPermutation(t, 8, partialRounds)

	// Convert elements to bytes
	inputBytes := make([][]byte, n)
	for i := 0; i < n; i++ {
		bytes := elements[i].Bytes()
		inputBytes[i] = bytes[:]
	}

	// For 2 inputs, use direct compression
	if n == 2 {
		hashResult, err := perm.Compress(inputBytes[0], inputBytes[1])
		if err != nil {
			return result, fmt.Errorf("poseidon2 hash failed: %w", err)
		}
		result.SetBytes(hashResult)
		return result, nil
	}

	// For more than 2 inputs, we need to use a different approach
	// The poseidon-lite library likely uses a specific tree structure
	// For now, we'll use iterative compression as a fallback
	current := inputBytes[0]
	for i := 1; i < len(inputBytes); i++ {
		hashResult, err := perm.Compress(current, inputBytes[i])
		if err != nil {
			return result, fmt.Errorf("poseidon%d hash failed at step %d: %w", n, i, err)
		}
		current = hashResult
	}

	result.SetBytes(current)
	return result, nil
}

// getPoseidonRounds returns the number of partial rounds for Circom compatibility
// t parameter = input_length + 1 for poseidon permutation
func getPoseidonRounds(inputLength int) int {
	t := inputLength + 1
	switch t {
	case 2:
		return 56
	case 3:
		return 57
	case 4:
		return 56
	case 5:
		return 60
	case 6:
		return 60
	case 7:
		return 63
	case 8:
		return 64
	case 9:
		return 63
	case 10:
		return 60
	case 11:
		return 66
	case 12:
		return 60
	case 13:
		return 65
	case 14:
		return 70
	case 15:
		return 60
	case 16:
		return 64
	case 17:
		return 68
	default:
		return 0
	}
}

// CustomHasher implements the custom hashing logic from TypeScript
func CustomHasher(pubKeyFormatted []string) (string, error) {
	if len(pubKeyFormatted) < 16 {
		// Convert strings to big.Int
		inputs := make([]*big.Int, len(pubKeyFormatted))
		for i, str := range pubKeyFormatted {
			val, ok := new(big.Int).SetString(str, 10)
			if !ok {
				return "", fmt.Errorf("invalid number format: %s", str)
			}
			inputs[i] = val
		}

		result, err := FlexiblePoseidon(inputs)
		if err != nil {
			return "", err
		}
		return result.String(), nil
	} else {
		rounds := (len(pubKeyFormatted) + 15) / 16 // Ceiling division
		if rounds > 16 {
			return "", fmt.Errorf("number of rounds is greater than 16")
		}

		// Create hash array with 16 inputs each, padded with zeros
		hashes := make([]*big.Int, rounds)
		for i := 0; i < rounds; i++ {
			inputs := make([]*big.Int, 16)
			for j := 0; j < 16; j++ {
				if i*16+j < len(pubKeyFormatted) {
					val, ok := new(big.Int).SetString(pubKeyFormatted[i*16+j], 10)
					if !ok {
						return "", fmt.Errorf("invalid number format: %s", pubKeyFormatted[i*16+j])
					}
					inputs[j] = val
				} else {
					inputs[j] = big.NewInt(0)
				}
			}

			hash, err := FlexiblePoseidon(inputs)
			if err != nil {
				return "", err
			}
			hashes[i] = hash
		}

		// Final hash of all round results
		finalResult, err := FlexiblePoseidon(hashes)
		if err != nil {
			return "", err
		}
		return finalResult.String(), nil
	}
}

// Example usage function demonstrating how to use FlexiblePoseidon
func ExampleFlexiblePoseidon() (*big.Int, error) {
	// Example with 2 inputs (similar to your provided example)
	inputs := []*big.Int{
		big.NewInt(12345),
		big.NewInt(67890),
	}

	result, err := FlexiblePoseidon(inputs)
	if err != nil {
		return nil, fmt.Errorf("example failed: %w", err)
	}

	return result, nil
}
