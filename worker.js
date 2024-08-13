onmessage = function(event) {	  
	
	// this worker is responsible for the entire Fuzzing process. 
	//
	// the worker will always return an array, where the value at index 0 will be a code regarding what type of callback this is. 
	//
	// code 0: the worker is done and will return all the collected information.
	// code 1: the worker will return the current values its fuzzing with back to the main thread every time it finished a test case.
	//         when its done it will return all the collected information.
	
	
	// loading initialized arrays and initialize temporarily vars. 
	gateTypes = event.data[0];
	gateConnections = event.data[1];
	gateStates = event.data[2];
	
	ioGatesIndexes = event.data[3];
	ioValues = [0, 0, 0];
	
	testConfig = event.data[4];
	rawChartData = [[], [], []];
	rawChartDataLoggedCases = [[], [], []];
	
	for(let x = 0; x < Math.pow(2, ioGatesIndexes[0].length); x++)
	{
		for(let y = 0; y < Math.pow(2, ioGatesIndexes[1].length); y++)
		{
			
			// initialize fuzzing Input/output values
			ioValues[0] = x;
			ioValues[1] = y;
			ioValues[2] = 0;
			
			// evaluate expected output and cut off all bits that go past the circuit output count
			let temp = testConfig[0].toString();
			temp = temp.replace(/A/g, x);
			temp = temp.replace(/B/g, y);
			let expectedOutput = evaluateExpression(temp)&((1 << ioGatesIndexes[2].length) - 1);
			
			// initialize gateStates array for all gates with state of 0
			gateStates = []
			for(let i = 0; i < gateTypes.length; i++){gateStates.push(0)};
			
			// declare and initialize vars to temporarily contain sim outcome values for this one sim only		
			let settleTime = 0;
			let outputTime = testConfig[1];
			
			// run the simulation for the test case, looping until no more gate states 
			// have changed after an UpdateLogic(). meanwhile collect outcome values and store them.
			for(let tickIndex = 0; tickIndex < testConfig[1]; tickIndex++)
			{
				// if the expected result hasnt yet been found, check for correctness
				if(outputTime == testConfig[1])
				{
					// get the circuit value as int output from the individual output gates 
					ioValues[2] = 0;
					for(let j = 0; j < ioGatesIndexes[2].length; j++)
					{ 
						ioValues[2] += (gateStates[ioGatesIndexes[2][j]] << j);
					}
					
					// if the expected result was found, Store the tickIndex to outputTime
					if(expectedOutput == ioValues[2])
					{
						outputTime = tickIndex+1;
					}
				}
				
				// if gate states havent changed after an UpdateLogic() call, end the test.
				settleTime++;
				if(!UpdateLogic())
				{
					break;
				}
			}
			
			if(settleTime == testConfig[1])
			{
				settleTime = 0;
			}
			if(outputTime == Number(testConfig[1]))
			{
				outputTime = 0;
			}
			
			// if any rawChartData sub-array isnt long enough to hold the to be inserted value, 
			// its getting extended until it does. rawChartDataLoggedCases will be affected the same way.
			while(settleTime >= rawChartData[0].length)
			{
				rawChartData[0].push(0);
				rawChartDataLoggedCases[0].push([]);
				// console.log(settleTime >= rawChartData[0].length)
			}
			while(outputTime >= rawChartData[1].length)
			{
				rawChartData[1].push(0);
				rawChartDataLoggedCases[1].push([]);
			}
			
			rawChartData[0][settleTime]++;
			rawChartData[1][outputTime]++;
			
			// store the test cases for each category at the corresponding index, 
			// if there are less than the max. allowed case records(testConfig[3]) in the array.
			if(rawChartDataLoggedCases[0][settleTime].length < testConfig[3])
			{
				//push io data
				rawChartDataLoggedCases[0][settleTime].push(ioValues.slice());
				//push expectedOutput
				rawChartDataLoggedCases[0][settleTime]
				[
					rawChartDataLoggedCases[0][settleTime].length-1
				].push(expectedOutput);
			}
			if(rawChartDataLoggedCases[1][outputTime].length < testConfig[3])
			{
				//push io data
				rawChartDataLoggedCases[1][outputTime].push(ioValues.slice());
				//push expectedOutput
				rawChartDataLoggedCases[1][outputTime]
				[
					rawChartDataLoggedCases[1][outputTime].length-1
				].push(expectedOutput);
			}
			
			//send x and y back to the main thread, so the progress bar can update.
			postMessage([1, [x, y]])
		}
	}
	
	// UpdateChart();

	postMessage([0, rawChartData, rawChartDataLoggedCases]);
}

function UpdateLogic() {
	let gateStatesNew = gateStates.slice(); // Create a new array to store the updated states

	for (let i = 0; i < gateStates.length; i++) {
		
		// gateTypes:
		// AND  = 0
		// OR   = 1
		// XOR  = 2
		// NAND = 3
		// NOR  = 4
		// XNOR = 5
		
		//and
		if(gateTypes[i] === 0)
		{
			let state = 1;
			if(gateConnections[i].length >= 1)
			{
				for (let j = 0; j < gateConnections[i].length; j++) 
				{
					if (gateStates[gateConnections[i][j]] == 0) 
					{
						state = 0;
						break;
					}
				}
			}
			else
			{
				state = 0;
			}
			gateStatesNew[i] = state;
		}
		
		//or
		else if (gateTypes[i] === 1) 
		{	  
			let state = 0;
			if(gateConnections[i].length >= 1)
			{
				for (let j = 0; j < gateConnections[i].length; j++) 
				{
					if (gateStates[gateConnections[i][j]] == 1) 
					{
						state = 1;
						break;
					}
				}
			}
			else
			{
				state = 0;
			}
			
			gateStatesNew[i] = state;
		}
		
		//xor
		else if (gateTypes[i] === 2) 
		{	  
			let state = 0;
			
			if(gateConnections[i].length >= 1)
			{
				for (let j = 0; j < gateConnections[i].length; j++) 
				{
					if (gateStates[gateConnections[i][j]] == 1) 
					{
						state = -state+1;
					}
				}
			}
			else
			{
				state = 0;
			}
			gateStatesNew[i] = state;
		}
	}
	
	//update the IO gate states
	for(let j = 0; j < ioGatesIndexes[0].length; j++)
	{
		gateStatesNew[ioGatesIndexes[0][j]] = (ioValues[0] >> j) & 1;
	}
	for(let j = 0; j < ioGatesIndexes[1].length; j++)
	{
		gateStatesNew[ioGatesIndexes[1][j]] = (ioValues[1] >> j) & 1;
	}
	
	//if all gate states are the same as before return false, otherwise return true
	for (let i = 0; i < gateStatesNew.length; i++) 
	{
		if (gateStatesNew[i] !== gateStates[i]) {
			gateStates = gateStatesNew.slice();
			return true;
		}
	}
	return false;
}

function tokenize(expression) {
	const tokens = [];
	let numberBuffer = [];
	
	for (const char of expression) {
		if (/\d/.test(char) || char === '.') {
			numberBuffer.push(char);
		} else if (/\s/.test(char)) {
			continue;
		} else {
			if (numberBuffer.length > 0) {
				tokens.push(numberBuffer.join(''));
				numberBuffer = [];
			}
			tokens.push(char);
		}
	}
	
	if (numberBuffer.length > 0) {
		tokens.push(numberBuffer.join(''));
	}
	
	return tokens;
}

function infixToRPN(tokens) {
	const outputQueue = [];
	const operatorStack = [];
	const precedence = {
		'+': 1,
		'-': 1,
		'*': 2,
		'/': 2,
		'%': 2,
		'&': 3,
		'|': 3,
		'^': 3,
		'<<': 3,
		'>>': 3
	};
	
	const associativity = {
		'+': 'L',
		'-': 'L',
		'*': 'L',
		'/': 'L',
		'%': 'L',
		'&': 'L',
		'|': 'L',
		'^': 'L',
		'<<': 'L',
		'>>': 'L'
	};
	
	tokens.forEach(token => {
		if (/\d/.test(token)) {
			outputQueue.push(token);
		} else if ('+-*/%&|^<>'.includes(token)) {
			while (operatorStack.length > 0 && '+-*/%&|^<>'.includes(operatorStack[operatorStack.length - 1]) &&
				   ((associativity[token] === 'L' && precedence[token] <= precedence[operatorStack[operatorStack.length - 1]]) ||
					(associativity[token] === 'R' && precedence[token] < precedence[operatorStack[operatorStack.length - 1]]))) {
				outputQueue.push(operatorStack.pop());
			}
			operatorStack.push(token);
		} else if (token === '(') {
			operatorStack.push(token);
		} else if (token === ')') {
			while (operatorStack.length > 0 && operatorStack[operatorStack.length - 1] !== '(') {
				outputQueue.push(operatorStack.pop());
			}
			operatorStack.pop(); // Pop '('
		}
	});
	
	while (operatorStack.length > 0) {
		outputQueue.push(operatorStack.pop());
	}
	
	return outputQueue;
}



function evaluateRPN(rpnTokens) {
	const stack = [];
	
	rpnTokens.forEach(token => {
		if (/\d/.test(token)) {
			stack.push(parseFloat(token));
		} else {
			const b = stack.pop();
			const a = stack.pop();
			switch (token) {
				case '+':
					stack.push(a + b);
					break;
				case '-':
					stack.push(a - b);
					break;
				case '*':
					stack.push(a * b);
					break;
				case '/':
					stack.push(a / b);
					break;
				case '%':
					stack.push(a % b);
					break;
				case '&':
					stack.push(a & b);
					break;
				case '|':
					stack.push(a | b);
					break;
				case '^':
					stack.push(a ^ b);
					break;
				case '<<':
					stack.push(a << b);
					break;
				case '>>':
					stack.push(a >> b);
					break;
			}
		}
	});
	
	return stack[0];
}


function evaluateExpression(expression) {
	const tokens = tokenize(expression);
	const rpn = infixToRPN(tokens);
	return evaluateRPN(rpn);
}