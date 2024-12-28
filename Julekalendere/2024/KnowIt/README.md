# Knowit kodekalender

## Dag 2

```py
teppe = [
    [0, 1, 1, 1, 0],
    [1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1],
    [0, 0, 1, 0, 0],
    [1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1],
    [1, 1, 1, 1, 1],
    [0, 1, 1, 1, 0]
]

mann = [
[0, 0, 0, 2, 2, 2, 0, 0, 0],
    [0, 0, 1, 1, 1, 1, 1, 0, 0],
    [0, 0, 1, 1, 1, 1, 1, 0, 0],
    [0, 0, 1, 1, 1, 1, 1, 0, 0],
    [0, 0, 0, 1, 1, 1, 0, 0, 0],
    [0, 0, 0, 0, 2, 0, 0, 0, 0],
    [0, 0, 0, 1, 2, 1, 0, 0, 0],
    [0, 0, 1, 2, 2, 2, 1, 0, 0],
    [0, 1, 1, 2, 2, 2, 1, 1, 0],
    [0, 1, 1, 2, 2, 2, 1, 1, 0],
    [0, 1, 1, 2, 2, 2, 1, 1, 0],
    [0, 1, 2, 2, 2, 2, 1, 1, 0],
    [0, 1, 2, 2, 3, 2, 1, 1, 0],
    [0, 1, 2, 3, 3, 2, 1, 1, 0],
    [0, 1, 2, 3, 3, 2, 1, 1, 0],
    [0, 1, 2, 3, 3, 2, 1, 1, 0],
    [0, 1, 2, 2, 3, 2, 1, 1, 0],
    [0, 2, 1, 2, 2, 2, 1, 2, 0],
    [0, 3, 1, 1, 2, 1, 1, 3, 0],
    [0, 0, 1, 1, 0, 1, 1, 0, 0],
    [0, 0, 1, 2, 0, 2, 1, 0, 0],
    [0, 0, 1, 2, 0, 2, 1, 0, 0],
    [0, 0, 2, 2, 0, 2, 2, 0, 0],
    [0, 0, 2, 3, 0, 3, 2, 0, 0],
    [0, 0, 2, 3, 0, 3, 2, 0, 0],
    [0, 0, 2, 3, 0, 3, 2, 0, 0],
    [0, 0, 2, 3, 0, 3, 2, 0, 0],
    [0, 0, 2, 3, 0, 3, 2, 0, 0],
    [6, 3, 3, 2, 0, 2, 3, 3, 6]
]

# Function to calculate overlay sum
def calculate_overlay_sum(arr1, arr2, start_row, start_col):
    rows1, cols1 = len(arr1), len(arr1[0])
    rows2, cols2 = len(arr2), len(arr2[0])
    result_sum = 0
    for i in range(rows1):
        for j in range(cols1):
            # Compute position in arr2
            row = start_row + i
            col = start_col + j
            # Multiply if position is within bounds of arr2, else assume 0
            if 0 <= row < rows2 and 0 <= col < cols2:
                result_sum += arr1[i][j] * arr2[row][col]
    return result_sum

# Function to transpose a 2D array by 90 degrees clockwise
def transpose_90_clockwise(array):
    return [list(row) for row in zip(*array[::-1])]

# Function to test all positions and find the maximum sum
def test_all_positions(teppe, mann, offset=5):
    rows1, cols1 = len(teppe), len(teppe[0])
    rows2, cols2 = len(mann), len(mann[0])

    max_sum = float('-inf')
    positions = []

    # Extend sliding range by the offset
    for start_row in range(-rows1 + 1 - offset, rows2 + offset):
        for start_col in range(-cols1 + 1 - offset, cols2 + offset):
            overlay_sum = calculate_overlay_sum(teppe, mann, start_row, start_col)
            if overlay_sum > max_sum:
                max_sum = overlay_sum
                positions = [(start_row, start_col)]
            elif overlay_sum == max_sum:
                positions.append((start_row, start_col))

    return max_sum, positions

# Test the original teppe
max_sum_original, positions_original = test_all_positions(teppe, mann, offset=5)

# Transpose teppe and test again
teppe_transposed = transpose_90_clockwise(teppe)
max_sum_transposed, positions_transposed = test_all_positions(teppe_transposed, mann, offset=5)

# Output the results
print("Original:", max_sum_original)
print("Rotert teppe:", max_sum_transposed)
```