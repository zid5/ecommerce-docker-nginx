const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

async function submitJson(url, payload, token = csrfToken) {
	const response = await fetch(url, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'X-CSRF-Token': token,
		},
		body: JSON.stringify(payload),
	});
	const result = await response.json();

	if (!response.ok) {
		throw new Error(result.error || 'The request could not be completed.');
	}
	return result;
}

function showError(messageElement, error) {
	messageElement.textContent = error.message || 'Something went wrong. Please try again.';
	messageElement.classList.remove('message-success');
	messageElement.classList.add('message-error');
}

const authForm = document.querySelector('#auth-form');
if (authForm) {
	const message = document.querySelector('#form-message');
	const submitButton = authForm.querySelector('button[type="submit"]');

	authForm.addEventListener('submit', async (event) => {
		event.preventDefault();
		message.textContent = '';
		submitButton.disabled = true;
		submitButton.querySelector('.button-label').textContent = 'Please wait...';

		const formData = new FormData(authForm);
		const payload = {
			email: formData.get('email'),
			password: formData.get('password'),
		};
		const action = authForm.dataset.authAction;
		if (action === 'signup') {
			payload.name = formData.get('name');
		}

		try {
			const result = await submitJson(`/api/auth/${action}`, payload);
			window.location.assign(result.redirect);
		} catch (error) {
			showError(message, error);
			submitButton.disabled = false;
			submitButton.querySelector('.button-label').textContent = action === 'signup' ? 'Create account' : 'Sign in';
		}
	});
}

const productForm = document.querySelector('#admin-product-form');
if (productForm) {
	const message = document.querySelector('#form-message');
	const submitButton = productForm.querySelector('button[type="submit"]');

	productForm.addEventListener('submit', async (event) => {
		event.preventDefault();
		message.textContent = '';
		message.className = 'form-message';
		submitButton.disabled = true;
		submitButton.querySelector('.button-label').textContent = 'Saving...';

		const formData = new FormData(productForm);
		const result = {
			name: formData.get('name').trim(),
			price: Number(formData.get('price')),
			category: formData.get('category').trim(),
			description: formData.get('description').trim(),
			imageUrl: formData.get('imageUrl').trim(),
		};

		try {
			await submitJson('/api/products', result);
			window.location.reload();
		} catch (error) {
			showError(message, error);
			submitButton.disabled = false;
			submitButton.querySelector('.button-label').textContent = 'Add product';
		}
	});
}

document.querySelectorAll('.logout-form').forEach((logoutForm) => {
	logoutForm.addEventListener('submit', async (event) => {
		event.preventDefault();
		const formData = new FormData(logoutForm);
		try {
			await submitJson('/api/auth/logout', {}, formData.get('csrfToken'));
			window.location.assign('/');
		} catch (error) {
			window.alert(error.message || 'Could not sign out. Please try again.');
		}
	});
});
