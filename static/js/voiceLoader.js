$(document).ready(function() {
  // Function to load voices and populate dropdowns
  function loadVoices() {
    const providers = ['openai', 'deepgram', 'gcloud', 'elevenlabs'];
    const dropdowns = ['#voice', '#editVoice']; // IDs of the dropdowns to populate

    providers.forEach(provider => {
      $.getJSON(`/static/js/${provider}.json`, function(data) {
        const optgroup = $('<optgroup>').attr('label', provider.charAt(0).toUpperCase() + provider.slice(1));
        data.forEach(voice => {
          const value = `${provider}.${voice.name}`;
          optgroup.append($('<option>').val(value).text(voice.name));
        });

        // Append options to each dropdown
        dropdowns.forEach(dropdownId => {
          $(dropdownId).append(optgroup.clone());
        });
      });
    });
  }

  loadVoices();

  // ... existing code ...
});
