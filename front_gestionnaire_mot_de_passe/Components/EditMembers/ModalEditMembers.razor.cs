using System.Text.Json;
using front_gestionnaire_mot_de_passe.Models.VaultMembers;
using Microsoft.AspNetCore.Components;
using Microsoft.Identity.Abstractions;

namespace front_gestionnaire_mot_de_passe.Components.EditMembers;

public partial class ModalEditMembers : ComponentBase
{
    [Parameter] public int VaultId { get; set; }
    [Parameter] public EventCallback OnClose { get; set; }

    [Inject] IDownstreamApi DownstreamApi { get; set; } = default!;

    public bool IsAddingMember { get; set; } = false;

    public List<GetUserObj>? UsersList { get; set; } = new List<GetUserObj>();

    public List<GetUserObj>? MembersAllreadyAdded { get; set; } = new List<GetUserObj>();

    protected override async Task OnInitializedAsync()
    {
        await RefreshLists();
    }

    public async Task RefreshLists()
    {
        HttpResponseMessage resUsersList = await DownstreamApi.CallApiForUserAsync(
                                               "DownstreamApi",
                                               options =>
                                               {
                                                   options.HttpMethod = HttpMethod.Get.Method;
                                                   options.RelativePath = $"/Users";
                                               })
                                           ?? throw new HttpRequestException(
                                               "An error occurred while fetching the resource.");

        HttpResponseMessage resMembersList = await DownstreamApi.CallApiForUserAsync(
                                                 "DownstreamApi",
                                                 options =>
                                                 {
                                                     options.HttpMethod = HttpMethod.Get.Method;
                                                     options.RelativePath = $"/VaultMember/{VaultId}";
                                                 })
                                             ?? throw new HttpRequestException(
                                                 "An error occurred while fetching the resource.");
        MembersAllreadyAdded = await resMembersList.Content.ReadFromJsonAsync<List<GetUserObj>>();
        UsersList = await resUsersList.Content.ReadFromJsonAsync<List<GetUserObj>>();
        UsersList = UsersList?.Where(u => MembersAllreadyAdded != null && MembersAllreadyAdded.All(m => m.Id != u.Id))
            .ToList();
        StateHasChanged();
    }

    public async Task AddMember(int userid)
    {
        try
        {
            var payload = new PostVaultMemeberObj
            {
                UserId = userid,
                VaultId = VaultId
            };

            await DownstreamApi.PostForUserAsync(
                "DownstreamApi",
                payload,
                options => { options.RelativePath = "/VaultMember"; });
          
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
        await RefreshLists();
    }

    private async Task RemoveMember(int memberId)
    {
        try
        {
            await DownstreamApi.CallApiForUserAsync(
                "DownstreamApi",
                options =>
                {
                    options.HttpMethod = HttpMethod.Delete.Method;
                    options.RelativePath = $"/VaultMember/{VaultId}/{memberId}";
                });
        
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
        await RefreshLists();
    }
}