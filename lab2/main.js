async function res(text, type) {
    const url = "http://localhost:9000/api/lab2";
    const response = await fetch(url, {
        method: 'POST',
        body: `{"input_text": "${text}", "type": "${type}"}`
    });
    response.json().then(data => {
        console.log(data);
        const output_text = document.querySelector('#decipher_output_text'); 
        if (type == '-s') {
            output_text.innerHTML = data.result.encryption;
        } else if (type == '-d') {
            output_text.innerHTML = data.result.decryption;
        } else {
            output_text.innerHTML = "Ошибка"
        }
    });  
}

document.addEventListener('DOMContentLoaded', () => { 
    const encryptionBtn = document.querySelector('#encryption_btn');
    const decipherBtn = document.querySelector('#decipher_btn');
    

    encryptionBtn.addEventListener('click', () => {
        const text = document.querySelector('#encryption_text').value;
        if (text != '') {
            res(text, '-s');
        } else {
            alert('Введине сообщение');
        }
    });

    decipherBtn.addEventListener('click', () => {
        const text = document.querySelector('#encryption_text').value;
        if (text != '') {
            res(text, '-d');
        } else {
            alert('Введине сообщение');
        }
    });
})