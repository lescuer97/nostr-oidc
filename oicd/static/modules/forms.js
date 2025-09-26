// modules/forms.js

// Init editable card name inputs
export function initCardInputs(root = document) {
  root.querySelectorAll('.card-name-input').forEach((input) => {
    const form = input.closest('form');
    if (!form) return;
    const saveBtn = form.querySelector('.card-save-btn');
    if (!saveBtn) return;

    // Ensure defaultValue is set to the initial value for comparison
    if (!input.defaultValue) {
      input.defaultValue = input.value;
    }

    const update = () => {
      const changed = input.value !== input.defaultValue;
      if (changed) {
        saveBtn.classList.remove('invisible');
      } else {
        saveBtn.classList.add('invisible');
      }
    };

    // Update visibility on input and change events
    input.addEventListener('input', update);
    input.addEventListener('change', update);

    // Initialize (make sure it's hidden if no changes)
    update();

    form.addEventListener('submit', () => {
      saveBtn.classList.add('hidden');
      saveBtn.setAttribute('aria-busy', 'true');
    });
  });
}
