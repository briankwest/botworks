$(document).ready(function () {
  function loadVoices() {
    const providers = ['openai', 'deepgram', 'gcloud', 'elevenlabs'];
    const dropdowns = ['#voice', '#editVoice'];

    providers.forEach(provider => {
      $.getJSON(`/static/js/${provider}.json`, function (data) {
        const optgroup = $('<optgroup>').attr('label', provider.charAt(0).toUpperCase() + provider.slice(1));
        data.forEach(voice => {
          const value = `${provider}.${voice.name}`;
          optgroup.append($('<option>').val(value).text(voice.name));
        });

        dropdowns.forEach(dropdownId => {
          $(dropdownId).append(optgroup.clone());
        });
      });
    });
  }

  loadVoices();
});
