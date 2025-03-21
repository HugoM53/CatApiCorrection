﻿#nullable disable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using DatabaseModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TheCatApiV2.Controller;
using TheCatApiV2.Data;

namespace TheCatApiV2.Areas.Identity.Pages.Account.Manage
{
    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    public class DownloadPersonalDataModel : PageModel
    {
        private DatabaseContext databaseContext;

        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<DownloadPersonalDataModel> _logger;

        private PictureJoinedController pictureJoinedController;

        public DownloadPersonalDataModel(
            UserManager<IdentityUser> userManager,
            ILogger<DownloadPersonalDataModel> logger,
            DatabaseContext GetDatabaseContext)
        {
            _userManager = userManager;
            _logger = logger;
            this.databaseContext = GetDatabaseContext;

            pictureJoinedController = new PictureJoinedController(databaseContext);
        }

        public IActionResult OnGet()
        {
            return NotFound();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Impossible de charger l'utilisateur avec l'ID '{_userManager.GetUserId(User)}'.");
            }

            _logger.LogInformation("L'utilisateur avec l'ID '{UserId}' a demandé ses données personnelles. Détails complets: {UserDetails}",
                _userManager.GetUserId(User), JsonSerializer.Serialize(user));

            // Rassemblement des données personnelles à télécharger
            var donnéesPersonnelles = new Dictionary<string, string>();
            var propriétésDonnéesPersonnelles = typeof(IdentityUser).GetProperties().Where(
                prop => Attribute.IsDefined(prop, typeof(PersonalDataAttribute)));
            foreach (var p in propriétésDonnéesPersonnelles)
            {
                donnéesPersonnelles.Add(p.Name, p.GetValue(user)?.ToString() ?? "null");
            }

            foreach (PictureJoinedDatabaseModel pictureJoined in this.pictureJoinedController.GetAllPicturesByUserId(user.Id))
            {
                donnéesPersonnelles.Add("Picture_" + pictureJoined.Id.ToString(), pictureJoined.ToString());
            }

            var logins = await _userManager.GetLoginsAsync(user);
            foreach (var l in logins)
            {
                donnéesPersonnelles.Add($"{l.LoginProvider} clé du fournisseur de connexion externe", l.ProviderKey);
            }

            donnéesPersonnelles.Add("Clé d'authentificateur", await _userManager.GetAuthenticatorKeyAsync(user));

            string fileName = Request.Query["filename"];
            if (string.IsNullOrEmpty(fileName))
            {
                fileName = "DonnéesPersonnelles.json";
            }
            Response.Headers.Add("Content-Disposition", $"attachment; filename={fileName}");
            return new FileContentResult(JsonSerializer.SerializeToUtf8Bytes(donnéesPersonnelles), "application/json");
        }
    }
}
